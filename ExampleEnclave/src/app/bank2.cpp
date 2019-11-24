/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "bank1.h"
#include "bank2.h"
#include "enclave_u.h"

#include "sample_libcrypto.h"

#include "ecp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include "ias_ra.h"
#include "enclave_attestation.h"
// #include "app.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif

using namespace std;

//TODO: Create a wrapper for the KPS, have it have the API, and basically
// when you call establishInitialConnection with KPS, you get a connectoin ID
// and the KPS is running on a thread, and whenever it gets a message with the correct
// connection ID, it calls the correct methods in thsi file and returns the results,
// if there are mulitple messages sent by mutiple connections, put them in a thred pool

//NOTE: in certain parts of this file, SP refers to the Ping machine

const int SIZE_OF_MESSAGE = 15000;

inline unordered_map<string, string> capabilityKeyAccessDictionary;
inline unordered_map<string, string> capabilityKeyDictionary;

inline char* serialize(double my_array[][3], int num_points) { //TODO: hardcoded dimension to be 3
    string bar;
    bar = "";
    for (int i=0 ; i<num_points; i++) {
        for (int j =0 ;j<3; j++) {
            bar += std::to_string(my_array[i][j]);
            bar += ',';
        }
    }
    char* to_ret = (char*)malloc(sizeof(char)*strlen(bar.c_str()));
    memcpy(to_ret, bar.c_str(), sizeof(char)*strlen(bar.c_str()));
    return to_ret;
}

//This represents the payload we are going to send to the enclave after a succesful attestation
//We write to this value in app.cpp before the ping machine initiates the attestation request with Pong enclave
inline char secure_message[SIZE_OF_MESSAGE]; 

// This is supported extended epid group of Ping machine. Ping machine can support more than one
// extended epid group with different extended epid group id and credentials.
inline static const sample_extended_epid_group g_extended_epid_groups[] = {
    {
        0,
        ias_enroll,
        ias_get_sigrl,
        ias_verify_attestation_evidence
    }
};

// This is the private part of the capability key. This is used to sign the authenticated
// DH between Ping machine and Pong enclave
inline static const sample_ec256_private_t g_sp_priv_key = {
    {
        0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
        0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
        0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
        0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
    }
};

// This is the public part of the capability key
inline static const sample_ec_pub_t g_sp_pub_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }
};

// This is a context data structure used for Ping Machine
typedef struct _sp_db_item_t
{
    sample_ec_pub_t             g_a;
    sample_ec_pub_t             g_b;
    sample_ec_key_128bit_t      vk_key;// Shared secret key for the REPORT_DATA
    sample_ec_key_128bit_t      mk_key;// Shared secret key for generating MAC's
    sample_ec_key_128bit_t      sk_key;// Shared secret key for encryption
    sample_ec_key_128bit_t      smk_key;// Used only for SIGMA protocol
    sample_ec_priv_t            b;
    sample_ps_sec_prop_desc_t   ps_sec_prop;
}sp_db_item_t;
static sp_db_item_t g_sp_db;

static const sample_extended_epid_group* g_sp_extended_epid_group_id= NULL;
static bool g_is_sp_registered = false;
static int g_sp_credentials = 0;
static int g_authentication_token = 0;

inline uint8_t g_secret[SIZE_OF_MESSAGE] = {0,1,2,3,4,5,6,7};

inline sample_spid_t g_spid;


//Code for parsing signed files to obtain expected measurement of enclave
#define MAX_LINE 4096
inline char* extract_measurement(FILE* fp)
{
  char *linha = (char*) malloc(MAX_LINE);
  int s, t;
  char lemma[100];
  bool match_found = false;
  char* measurement = (char*) malloc(100);
  int i = 0;
  while(fgets(linha, MAX_LINE, fp))
  {
      //printf("%s", linha);
    if (strcmp(linha, "metadata->enclave_css.body.isv_prod_id: 0x0\n") == 0) {
        //printf("%s", linha);
        //printf("%s", measurement);
        //printf("\nEnd found!\n");
        measurement[i] = '\0';
        return measurement;
    }
    if (match_found == true) {
        int len = strlen( linha );
        bool skip = true;
        for (int k = 0; k < len; k++) {
            if (linha[k] == '\\') {
                break;
            }
            if (linha[k] == ' ') {
                continue;
            }
            if (skip) {
                skip = false;
                k++;
            } else {
                skip = true;
                measurement[i] = linha[k];
                i++;
                k++;
                measurement[i] = linha[k];
                i++;
            }
            
        }
    }
    if (strcmp(linha, "metadata->enclave_css.body.enclave_hash.m:\n") == 0) {
        //printf("MATCH FOUND\n");
        match_found = true;
    }   
   }

   return NULL;
}
//


// Verify message 0 then configure extended epid group.
int bank2_sp_ra_proc_msg0_req(const sample_ra_msg0_t *p_msg0,
    uint32_t msg0_size)
{
    int ret = -1;

    if (!p_msg0 ||
        (msg0_size != sizeof(sample_ra_msg0_t)))
    {
        return -1;
    }
    uint32_t extended_epid_group_id = p_msg0->extended_epid_group_id;

    // Check to see if we have registered with the attestation server yet?
    if (!g_is_sp_registered ||
        (g_sp_extended_epid_group_id != NULL && g_sp_extended_epid_group_id->extended_epid_group_id != extended_epid_group_id))
    {
        // Check to see if the extended_epid_group_id is supported?
        ret = SP_UNSUPPORTED_EXTENDED_EPID_GROUP;
        for (size_t i = 0; i < sizeof(g_extended_epid_groups) / sizeof(sample_extended_epid_group); i++)
        {
            if (g_extended_epid_groups[i].extended_epid_group_id == extended_epid_group_id)
            {
                g_sp_extended_epid_group_id = &(g_extended_epid_groups[i]);
                // In the product, the Ping Machine will establish a mutually
                // authenticated SSL channel. During the enrollment process, the ISV
                // registers it exchanges TLS certs with attestation server and obtains an SPID and
                // Report Key from the attestation server.
                // For a product attestation server, enrollment is an offline process.  See the 'on-boarding'
                // documentation to get the information required.  The enrollment process is
                // simulated by a call in this sample.
                ret = g_sp_extended_epid_group_id->enroll(g_sp_credentials, &g_spid,
                    &g_authentication_token);
                if (0 != ret)
                {
                    ret = SP_IAS_FAILED;
                    break;
                }

                g_is_sp_registered = true;
                ret = SP_OK;
                break;
            }
        }
    }
    else
    {
        ret = SP_OK;
    }

    return ret;
}

// Verify message 1 then generate and return message 2 to isv.
int bank2_sp_ra_proc_msg1_req(const sample_ra_msg1_t *p_msg1,
						uint32_t msg1_size,
						ra_samp_response_header_t **pp_msg2)
{
    int ret = 0;
    ra_samp_response_header_t* p_msg2_full = NULL;
    sample_ra_msg2_t *p_msg2 = NULL;
    sample_ecc_state_handle_t ecc_state = NULL;
    sample_status_t sample_ret = SAMPLE_SUCCESS;
    bool derive_ret = false;

    if(!p_msg1 ||
       !pp_msg2 ||
       (msg1_size != sizeof(sample_ra_msg1_t)))
    {
        return -1;
    }

    // Check to see if we have registered?
    if (!g_is_sp_registered)
    {
        return SP_UNSUPPORTED_EXTENDED_EPID_GROUP;
    }

    do
    {
        // Get the sig_rl from attestation server using GID.
        // GID is Base-16 encoded of EPID GID in little-endian format.
        // In the product, the SP and attesation server uses an established channel for
        // communication.
        uint8_t* sig_rl;
        uint32_t sig_rl_size = 0;

        // The product interface uses a REST based message to get the SigRL.
        
        ret = g_sp_extended_epid_group_id->get_sigrl(p_msg1->gid, &sig_rl_size, &sig_rl);
        if(0 != ret)
        {
            fprintf(stderr, "\nError, ias_get_sigrl [%s].", __FUNCTION__);
            ret = SP_IAS_FAILED;
            break;
        }

        // Need to save the client's public ECCDH key to local storage
        if (memcpy_s(&g_sp_db.g_a, sizeof(g_sp_db.g_a), &p_msg1->g_a,
                     sizeof(p_msg1->g_a)))
        {
            fprintf(stderr, "\nError, cannot do memcpy in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Generate the Service providers ECCDH key pair.
        sample_ret = sample_ecc256_open_context(&ecc_state);
        if(SAMPLE_SUCCESS != sample_ret)
        {
            fprintf(stderr, "\nError, cannot get ECC context in [%s].",
                             __FUNCTION__);
            ret = -1;
            break;
        }
        sample_ec256_public_t pub_key = {{0},{0}};
        sample_ec256_private_t priv_key = {{0}};
        sample_ret = sample_ecc256_create_key_pair(&priv_key, &pub_key,
                                                   ecc_state);
        if(SAMPLE_SUCCESS != sample_ret)
        {
            fprintf(stderr, "\nError, cannot generate key pair in [%s].",
                    __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Need to save the SP ECCDH key pair to local storage.
        if(memcpy_s(&g_sp_db.b, sizeof(g_sp_db.b), &priv_key,sizeof(priv_key))
           || memcpy_s(&g_sp_db.g_b, sizeof(g_sp_db.g_b),
                       &pub_key,sizeof(pub_key)))
        {
            fprintf(stderr, "\nError, cannot do memcpy in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Generate the client/SP shared secret
        sample_ec_dh_shared_t dh_key = {{0}};
        sample_ret = sample_ecc256_compute_shared_dhkey(&priv_key,
            (sample_ec256_public_t *)&p_msg1->g_a,
            (sample_ec256_dh_shared_t *)&dh_key,
            ecc_state);
        if(SAMPLE_SUCCESS != sample_ret)
        {
            fprintf(stderr, "\nError, compute share key fail in [%s].",
                    __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

#ifdef SUPPLIED_KEY_DERIVATION

        // smk is only needed for msg2 generation.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SMK_SK,
            &g_sp_db.smk_key, &g_sp_db.sk_key);
        if(derive_ret != true)
        {
            fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // The rest of the keys are the shared secrets for future communication.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_MK_VK,
            &g_sp_db.mk_key, &g_sp_db.vk_key);
        if(derive_ret != true)
        {
            fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
#else
        // smk is only needed for msg2 generation.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SMK,
                                &g_sp_db.smk_key);
        if(derive_ret != true)
        {
            fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // The rest of the keys are the shared secrets for future communication.
        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_MK,
                                &g_sp_db.mk_key);
        if(derive_ret != true)
        {
            fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_SK,
                                &g_sp_db.sk_key);
        if(derive_ret != true)
        {
            fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        derive_ret = derive_key(&dh_key, SAMPLE_DERIVE_KEY_VK,
                                &g_sp_db.vk_key);
        if(derive_ret != true)
        {
            fprintf(stderr, "\nError, derive key fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
#endif

        uint32_t msg2_size = (uint32_t)sizeof(sample_ra_msg2_t) + sig_rl_size;
        p_msg2_full = (ra_samp_response_header_t*)malloc(msg2_size
                      + sizeof(ra_samp_response_header_t));
        if(!p_msg2_full)
        {
            fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        memset(p_msg2_full, 0, msg2_size + sizeof(ra_samp_response_header_t));
        p_msg2_full->type = TYPE_RA_MSG2;
        p_msg2_full->size = msg2_size;
        // The simulated message2 always passes.  This would need to be set
        // accordingly in a real service provider implementation.
        p_msg2_full->status[0] = 0;
        p_msg2_full->status[1] = 0;
        p_msg2 = (sample_ra_msg2_t *)p_msg2_full->body;

        // Assemble MSG2
        if(memcpy_s(&p_msg2->g_b, sizeof(p_msg2->g_b), &g_sp_db.g_b,
                    sizeof(g_sp_db.g_b)) ||
           memcpy_s(&p_msg2->spid, sizeof(sample_spid_t),
                    &g_spid, sizeof(g_spid)))
        {
            fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // The service provider is responsible for selecting the proper EPID
        // signature type and to understand the implications of the choice!
        p_msg2->quote_type = SAMPLE_QUOTE_LINKABLE_SIGNATURE;

#ifdef SUPPLIED_KEY_DERIVATION
//isv defined key derivation function id
#define ISV_KDF_ID 2
        p_msg2->kdf_id = ISV_KDF_ID;
#else
        p_msg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;
#endif
        // Create gb_ga
        sample_ec_pub_t gb_ga[2];
        if(memcpy_s(&gb_ga[0], sizeof(gb_ga[0]), &g_sp_db.g_b,
                    sizeof(g_sp_db.g_b))
           || memcpy_s(&gb_ga[1], sizeof(gb_ga[1]), &g_sp_db.g_a,
                       sizeof(g_sp_db.g_a)))
        {
            fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Sign gb_ga
        sample_ret = sample_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga),
                        (sample_ec256_private_t *)&g_sp_priv_key,
                        (sample_ec256_signature_t *)&p_msg2->sign_gb_ga,
                        ecc_state);
        if(SAMPLE_SUCCESS != sample_ret)
        {
            fprintf(stderr, "\nError, sign ga_gb fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        // Generate the CMACsmk for gb||SPID||TYPE||KDF_ID||Sigsp(gb,ga)
        uint8_t mac[SAMPLE_EC_MAC_SIZE] = {0};
        uint32_t cmac_size = offsetof(sample_ra_msg2_t, mac);
        sample_ret = sample_rijndael128_cmac_msg(&g_sp_db.smk_key,
            (uint8_t *)&p_msg2->g_b, cmac_size, &mac);
        if(SAMPLE_SUCCESS != sample_ret)
        {
            fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        if(memcpy_s(&p_msg2->mac, sizeof(p_msg2->mac), mac, sizeof(mac)))
        {
            fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        if(memcpy_s(&p_msg2->sig_rl[0], sig_rl_size, sig_rl, sig_rl_size))
        {
            fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        p_msg2->sig_rl_size = sig_rl_size;

    }while(0);

    if(ret)
    {
        *pp_msg2 = NULL;
        SAFE_FREE(p_msg2_full);
    }
    else
    {
        // Freed by the network simulator in ra_free_network_response_buffer
        *pp_msg2 = p_msg2_full;
    }

    if(ecc_state)
    {
        sample_ecc256_close_context(ecc_state);
    }

    return ret;
}

// Process remote attestation message 3
int bank2_sp_ra_proc_msg3_req(const sample_ra_msg3_t *p_msg3,
                        uint32_t msg3_size,
                        ra_samp_response_header_t **pp_att_result_msg,
                        int message_from_machine_to_enclave,
                        char* optional_message) //message_from_machine_to_enclave is 1 when the enclave is supposed to receive a message
                                                             //0 when the enclave is suppposed to send a message
{
    int ret = 0;
    sample_status_t sample_ret = SAMPLE_SUCCESS;
    const uint8_t *p_msg3_cmaced = NULL;
    const sample_quote_t *p_quote = NULL;
    sample_sha_state_handle_t sha_handle = NULL;
    sample_report_data_t report_data = {0};
    sample_ra_att_result_msg_t *p_att_result_msg = NULL;
    ra_samp_response_header_t* p_att_result_msg_full = NULL;
    uint32_t i;

    if((!p_msg3) ||
       (msg3_size < sizeof(sample_ra_msg3_t)) ||
       (!pp_att_result_msg))
    {
        return SP_INTERNAL_ERROR;
    }

    // Check to see if we have registered?
    if (!g_is_sp_registered)
    {
        return SP_UNSUPPORTED_EXTENDED_EPID_GROUP;
    }
    do
    {
        // Compare g_a in message 3 with local g_a.
        ret = memcmp(&g_sp_db.g_a, &p_msg3->g_a, sizeof(sample_ec_pub_t));
        if(ret)
        {
            fprintf(stderr, "\nError, g_a is not same [%s].", __FUNCTION__);
            ret = SP_PROTOCOL_ERROR;
            break;
        }
        //Make sure that msg3_size is bigger than sample_mac_t.
        uint32_t mac_size = msg3_size - (uint32_t)sizeof(sample_mac_t);
        p_msg3_cmaced = reinterpret_cast<const uint8_t*>(p_msg3);
        p_msg3_cmaced += sizeof(sample_mac_t);

        // Verify the message mac using SMK
        sample_cmac_128bit_tag_t mac = {0};
        sample_ret = sample_rijndael128_cmac_msg(&g_sp_db.smk_key,
                                           p_msg3_cmaced,
                                           mac_size,
                                           &mac);
        if(SAMPLE_SUCCESS != sample_ret)
        {
            fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        // In real implementation, should use a time safe version of memcmp here,
        // in order to avoid side channel attack.
        ret = memcmp(&p_msg3->mac, mac, sizeof(mac));
        if(ret)
        {
            fprintf(stderr, "\nError, verify cmac fail [%s].", __FUNCTION__);
            ret = SP_INTEGRITY_FAILED;
            break;
        }

        if(memcpy_s(&g_sp_db.ps_sec_prop, sizeof(g_sp_db.ps_sec_prop),
            &p_msg3->ps_sec_prop, sizeof(p_msg3->ps_sec_prop)))
        {
            fprintf(stderr,"\nError, memcpy failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        p_quote = (const sample_quote_t*)p_msg3->quote;

        // Check the quote version if needed. Only check the Quote.version field if the enclave
        // identity fields have changed or the size of the quote has changed.  The version may
        // change without affecting the legacy fields or size of the quote structure.
        //if(p_quote->version < ACCEPTED_QUOTE_VERSION)
        //{
        //    fprintf(stderr,"\nError, quote version is too old.", __FUNCTION__);
        //    ret = SP_QUOTE_VERSION_ERROR;
        //    break;
        //}

        // Verify the report_data in the Quote matches the expected value.
        // The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
        // The second 32 bytes of report_data are set to zero.
        sample_ret = sample_sha256_init(&sha_handle);
        if(sample_ret != SAMPLE_SUCCESS)
        {
            fprintf(stderr,"\nError, init hash failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.g_a),
                                     sizeof(g_sp_db.g_a), sha_handle);
        if(sample_ret != SAMPLE_SUCCESS)
        {
            fprintf(stderr,"\nError, udpate hash failed in [%s].",
                    __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.g_b),
                                     sizeof(g_sp_db.g_b), sha_handle);
        if(sample_ret != SAMPLE_SUCCESS)
        {
            fprintf(stderr,"\nError, udpate hash failed in [%s].",
                    __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        sample_ret = sample_sha256_update((uint8_t *)&(g_sp_db.vk_key),
                                     sizeof(g_sp_db.vk_key), sha_handle);
        if(sample_ret != SAMPLE_SUCCESS)
        {
            fprintf(stderr,"\nError, udpate hash failed in [%s].",
                    __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        sample_ret = sample_sha256_get_hash(sha_handle,
                                      (sample_sha256_hash_t *)&report_data);
        if(sample_ret != SAMPLE_SUCCESS)
        {
            fprintf(stderr,"\nError, Get hash failed in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        ret = memcmp((uint8_t *)&report_data,
                     &(p_quote->report_body.report_data),
                     sizeof(report_data));
        if(ret)
        {
            fprintf(stderr, "\nError, verify hash fail [%s].", __FUNCTION__);
            ret = SP_INTEGRITY_FAILED;
            break;
        }


        //Verify the measurement of the enclave is the same as the expected measurement from the file
        FILE *fp1 = fopen("metadata_info.txt", "r"); 
        if (fp1 == NULL) 
        { 
            printf("Error : File not open"); 
            exit(0); 
        } 

        char* expected_measurement = extract_measurement(fp1);
        char* actual_measurement = (char*) malloc(100);
        char* ptr = actual_measurement;

        if (ENABLE_KPS_ATTESTATION_PRINT) {
            printf("Expected Measurement is: %s\n", expected_measurement);
        }

        for(i=0;i<sizeof(sample_measurement_t);i++)
        {
            sprintf(ptr, "%02x",p_quote->report_body.mr_enclave[i]);
            ptr += 2;
        }
        ptr[i] = '\0';

        if (ENABLE_KPS_ATTESTATION_PRINT) {
            printf("Actual Measurement is: %s\n", actual_measurement);
        }

        //If measurements differ, we need to abort this connection
        if (!(strcmp(expected_measurement, actual_measurement) == 0)) {
            printf("MEASUREMENT ERROR!");
            //TODO uncommmet the below when you figure out why measurement check is failing now
            //even though it wasn't failing before this commit
            ret = SP_QUOTE_VERIFICATION_FAILED;
            break;
        }    
        fclose(fp1); 



        // Verify Enclave policy (an attestation server may provide an API for this if we
        // registered an Enclave policy)

        // Verify quote with attestation server.
        // In the product, an attestation server could use a REST message and JSON formatting to request
        // attestation Quote verification.  The sample only simulates this interface.
        ias_att_report_t attestation_report;
        memset(&attestation_report, 0, sizeof(attestation_report));
        ret = g_sp_extended_epid_group_id->verify_attestation_evidence(p_quote, NULL,
                                              &attestation_report);
        if(0 != ret)
        {
            ret = SP_IAS_FAILED;
            break;
        }
        FILE* OUTPUT;
        if (ENABLE_KPS_ATTESTATION_PRINT) {
            OUTPUT = stdout;
        } else {
            OUTPUT =  fopen ("temper.txt" , "w");
        }

        fprintf(OUTPUT, "\n\n\tAttestation Report:");
        fprintf(OUTPUT, "\n\tid: 0x%0x.", attestation_report.id);
        fprintf(OUTPUT, "\n\tstatus: %d.", attestation_report.status);
        fprintf(OUTPUT, "\n\trevocation_reason: %u.",
                attestation_report.revocation_reason);
        // attestation_report.info_blob;
        fprintf(OUTPUT, "\n\tpse_status: %d.",  attestation_report.pse_status);
        
        // Note: This sample always assumes the PIB is sent by attestation server.  In the product
        // implementation, the attestation server could only send the PIB for certain attestation 
        // report statuses.  A product SP implementation needs to handle cases
        // where the PIB is zero length.

        // Respond the client with the results of the attestation.
        uint32_t att_result_msg_size = sizeof(sample_ra_att_result_msg_t);
        p_att_result_msg_full =
            (ra_samp_response_header_t*)malloc(att_result_msg_size
            + sizeof(ra_samp_response_header_t) + sizeof(g_secret));
        if(!p_att_result_msg_full)
        {
            fprintf(stderr, "\nError, out of memory in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }
        memset(p_att_result_msg_full, 0, att_result_msg_size
               + sizeof(ra_samp_response_header_t) + sizeof(g_secret));
        p_att_result_msg_full->type = TYPE_RA_ATT_RESULT;
        p_att_result_msg_full->size = att_result_msg_size;
        if(IAS_QUOTE_OK != attestation_report.status)
        {
            p_att_result_msg_full->status[0] = 0xFF;
        }
        if(IAS_PSE_OK != attestation_report.pse_status)
        {
            p_att_result_msg_full->status[1] = 0xFF;
        }

        p_att_result_msg =
            (sample_ra_att_result_msg_t *)p_att_result_msg_full->body;

        // In a product implementation of attestation server, the HTTP response header itself could have
        // an RK based signature that the service provider needs to check here.

        // The platform_info_blob signature will be verified by the client
        // when sent. No need to have the Service Provider to check it.  The SP
        // should pass it down to the application for further analysis.

        fprintf(OUTPUT, "\n\n\tEnclave Report:");
        fprintf(OUTPUT, "\n\tSignature Type: 0x%x", p_quote->sign_type);
        fprintf(OUTPUT, "\n\tSignature Basename: ");
        for(i=0; i<sizeof(p_quote->basename.name) && p_quote->basename.name[i];
            i++)
        {
            fprintf(OUTPUT, "%c", p_quote->basename.name[i]);
        }
#ifdef __x86_64__
        fprintf(OUTPUT, "\n\tattributes.flags: 0x%0lx",
                p_quote->report_body.attributes.flags);
        fprintf(OUTPUT, "\n\tattributes.xfrm: 0x%0lx",
                p_quote->report_body.attributes.xfrm);
#else
        fprintf(OUTPUT, "\n\tattributes.flags: 0x%0llx",
                p_quote->report_body.attributes.flags);
        fprintf(OUTPUT, "\n\tattributes.xfrm: 0x%0llx",
                p_quote->report_body.attributes.xfrm);
#endif
        fprintf(OUTPUT, "\n\tmr_enclave: ");
        for(i=0;i<sizeof(sample_measurement_t);i++)
        {

            fprintf(OUTPUT, "%02x",p_quote->report_body.mr_enclave[i]);

            //fprintf(stderr, "%02x",p_quote->report_body.mr_enclave.m[i]);

        }
        fprintf(OUTPUT, "\n\tmr_signer: ");
        for(i=0;i<sizeof(sample_measurement_t);i++)
        {

            fprintf(OUTPUT, "%02x",p_quote->report_body.mr_signer[i]);

            //fprintf(stderr, "%02x",p_quote->report_body.mr_signer.m[i]);

        }
        fprintf(OUTPUT, "\n\tisv_prod_id: 0x%0x",
                p_quote->report_body.isv_prod_id);
        fprintf(OUTPUT, "\n\tisv_svn: 0x%0x",p_quote->report_body.isv_svn);
        fprintf(OUTPUT, "\n");

        // A product service provider needs to verify that its enclave properties 
        // match what is expected.  The SP needs to check these values before
        // trusting the enclave.  For the sample, we always pass the policy check.
        // Attestation server only verifies the quote structure and signature.  It does not 
        // check the identity of the enclave.
        bool isv_policy_passed = true;

        // Assemble Attestation Result Message
        // Note, this is a structure copy.  We don't copy the policy reports
        // right now.
        p_att_result_msg->platform_info_blob = attestation_report.info_blob;

        // Generate mac based on the mk key.
        mac_size = sizeof(ias_platform_info_blob_t);
        sample_ret = sample_rijndael128_cmac_msg(&g_sp_db.mk_key,
            (const uint8_t*)&p_att_result_msg->platform_info_blob,
            mac_size,
            &p_att_result_msg->mac);
        if(SAMPLE_SUCCESS != sample_ret)
        {
            fprintf(stderr, "\nError, cmac fail in [%s].", __FUNCTION__);
            ret = SP_INTERNAL_ERROR;
            break;
        }

        //We need to send the secure message in this case to the enclave 
        if (message_from_machine_to_enclave == CREATE_CAPABILITY_KEY_CONSTANT) { 

            // //Generate the capability key
            // char* split = strtok(optional_message, ":");
            // char* childID = split;
            // split = strtok(NULL, ":");
            // char* parentID = split;

            // createCapabilityKey(childID, parentID);

            if (TEST_CONSTANT == 0) {
                double kirat_data[30][3] = {{0.9081675950083055,0.9081675950083055,0.9081675950083055},{0.9167215466433015,0.9167215466433015,0.9167215466433015},{0.8922306368258723,0.8922306368258723,0.8922306368258723},{0.9163463050131526,0.9163463050131526,0.9163463050131526},{0.9042397040960038,0.9042397040960038,0.9042397040960038},{0.9049571448274706,0.9049571448274706,0.9049571448274706},{0.8981490887987427,0.8981490887987427,0.8981490887987427},{0.8860200663613924,0.8860200663613924,0.8860200663613924},{0.900912256877903,0.900912256877903,0.900912256877903},{0.8959109343915358,0.8959109343915358,0.8959109343915358},{0.8970430120772672,0.8970430120772672,0.8970430120772672},{0.9029120003866563,0.9029120003866563,0.9029120003866563},{0.9112702999606773,0.9112702999606773,0.9112702999606773},{0.8995570642703542,0.8995570642703542,0.8995570642703542},{0.900068574605907,0.900068574605907,0.900068574605907},{0.9033991377238719,0.9033991377238719,0.9033991377238719},{0.8888194555316604,0.8888194555316604,0.8888194555316604},{0.8999100358215115,0.8999100358215115,0.8999100358215115},{0.8740608415262292,0.8740608415262292,0.8740608415262292},{0.8976274545955861,0.8976274545955861,0.8976274545955861},{0.919480357139294,0.919480357139294,0.919480357139294},{0.9001299776113914,0.9001299776113914,0.9001299776113914},{0.9109115936626112,0.9109115936626112,0.9109115936626112},{0.9176965877955311,0.9176965877955311,0.9176965877955311},{0.8996853626211772,0.8996853626211772,0.8996853626211772},{0.9171306250899065,0.9171306250899065,0.9171306250899065},{0.8942957668659768,0.8942957668659768,0.8942957668659768},{0.90506280312969,0.90506280312969,0.90506280312969},{0.8988188251658166,0.8988188251658166,0.8988188251658166},{0.9130477624054308,0.9130477624054308,0.9130477624054308}};
                // {0.6077049930996429,0.6077049930996429,0.6077049930996429},{0.5911618817816682,0.5911618817816682,0.5911618817816682},{0.5982867199332335,0.5982867199332335,0.5982867199332335},{0.605950938928775,0.605950938928775,0.605950938928775},{0.6165454308890274,0.6165454308890274,0.6165454308890274},{0.5937022166689185,0.5937022166689185,0.5937022166689185},{0.5990321836737337,0.5990321836737337,0.5990321836737337},{0.5871030592614939,0.5871030592614939,0.5871030592614939},{0.5930022282063667,0.5930022282063667,0.5930022282063667},{0.6130757252683101,0.6130757252683101,0.6130757252683101},{0.5978220475471928,0.5978220475471928,0.5978220475471928},{0.5872872348637117,0.5872872348637117,0.5872872348637117},{0.5880892314515322,0.5880892314515322,0.5880892314515322},{0.6070730159438522,0.6070730159438522,0.6070730159438522},{0.5894143782658511,0.5894143782658511,0.5894143782658511},{0.599005391327391,0.599005391327391,0.599005391327391},{0.6036133597799735,0.6036133597799735,0.6036133597799735},{0.6072065062391973,0.6072065062391973,0.6072065062391973},{0.5996041984673666,0.5996041984673666,0.5996041984673666},{0.6118012000166696,0.6118012000166696,0.6118012000166696},{0.5939191739484727,0.5939191739484727,0.5939191739484727},{0.5886750065063125,0.5886750065063125,0.5886750065063125},{0.5997426684771702,0.5997426684771702,0.5997426684771702},{0.6102334863401919,0.6102334863401919,0.6102334863401919},{0.5912972333278679,0.5912972333278679,0.5912972333278679},{0.6025604243740265,0.6025604243740265,0.6025604243740265},{0.6219972918131564,0.6219972918131564,0.6219972918131564},{0.5923896403159432,0.5923896403159432,0.5923896403159432},{0.6027579545288441,0.6027579545288441,0.6027579545288441},{0.5919086122601278,0.5919086122601278,0.5919086122601278},{0.5893599381995716,0.5893599381995716,0.5893599381995716},{0.5810214653023501,0.5810214653023501,0.5810214653023501},{0.589016806862104,0.589016806862104,0.589016806862104},{0.5911380139516503,0.5911380139516503,0.5911380139516503},{0.5970084355685829,0.5970084355685829,0.5970084355685829},{0.5993451823616759,0.5993451823616759,0.5993451823616759},{0.6033988664617769,0.6033988664617769,0.6033988664617769},{0.6096485616936191,0.6096485616936191,0.6096485616936191},{0.6025352417947997,0.6025352417947997,0.6025352417947997},{0.5897520322856289,0.5897520322856289,0.5897520322856289}
                char* data_str = serialize(kirat_data, 30);
                printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 1) {
                double kirat_data[60][3] = {{0.6187364287207288,0.600800945922147,0.603334116103371},{0.5930278057939778,0.607640482912506,0.5958849754787588},{0.6039615572006313,0.6028887181256956,0.600673559850454},{0.5940360255414805,0.6028511127987501,0.5971663094489347},{0.6129588826252251,0.6155260839492239,0.5877695257908313},{0.5881485259586482,0.6015542105965628,0.5990152035992073},{0.5949420965113984,0.6102263006232801,0.5736833935431273},{0.6058566948161551,0.5932758783027793,0.5890690100962037},{0.5952749474589082,0.6194053469671381,0.602541492870488},{0.5962797792427382,0.5975575912147485,0.5863864661578178},{0.5845510382665636,0.6113876873922162,0.5975031758492425},{0.5943288409918219,0.6000189559084974,0.6077672604719477},{0.6092578258106999,0.5991358520684774,0.5989581811231403},{0.6038314043719251,0.6025178788160626,0.6018415483608066},{0.5891181572589421,0.5854348957212644,0.6013272346659545},{0.6073410294307531,0.6059125176148579,0.6124858715281954},{0.5905261288056297,0.6160656395110535,0.6200978710711905},{0.6132252389943544,0.5970716378341752,0.5946416868103792},{0.5943350959021941,0.6074291422476883,0.5982650260475532},{0.5942009610145242,0.60990934440221,0.5872901710247488},{0.6196873647981207,0.6071086703475658,0.595824035369261},{0.6100414489930388,0.62249915980559,0.6122694976301537},{0.6014235672094899,0.5891907129316915,0.6041800529448969},{0.5898334520405981,0.5902491836963534,0.6002836961092421},{0.6128368903124406,0.6095563763429952,0.5943694809622874},{0.5996636335001092,0.6002750017507538,0.6065350757107888},{0.5824503453225562,0.5765035418967925,0.6037243122546581},{0.6124204597725553,0.6025595181295648,0.6151749288817298},{0.6064932018346343,0.6037092811769383,0.6083234782898346},{0.5910901797979264,0.5885512687096662,0.608015862533139},{0.6035810753875968,0.6006835281840536,0.5976656797218574},{0.5897340553100354,0.6025355893436976,0.5977794338347776},{0.5943376579202655,0.599571051907653,0.5815089211568618},{0.5899057741480594,0.6111524011011187,0.5803906474358325},{0.6104350874922537,0.5912444909663076,0.5832322223867563},{0.5954155541726015,0.6135419990532142,0.5954020912814599},{0.6042222360164815,0.5995322662891375,0.5895933666013928},{0.6089696935992336,0.6009168577083753,0.594572427420679},{0.6142704063400062,0.6081565536366039,0.5975507441723625},{0.582949507758812,0.6030004984243617,0.6049154395153313},{0.609430984558263,0.5815126982617705,0.5900795775234579},{0.5954078754128874,0.5840049329600557,0.6041552783886932},{0.5860137838284742,0.5912588461416106,0.5992855615334728},{0.5920288841370325,0.5993007721744285,0.6073996860153866},{0.6109165502927868,0.6022913026922254,0.5863698111686025},{0.600420075711764,0.5920575488924474,0.5868595873849792},{0.6070352031726015,0.5925087898905144,0.5867908237943346},{0.5909973712666811,0.5797094459275766,0.6112185755988242},{0.5877246966952473,0.6072180395285758,0.5867102205934177},{0.6022856856756291,0.5897331512695873,0.5980285634182139},{0.5922365906538323,0.5999944294448081,0.6046360802255298},{0.5996057343705932,0.6113676951629221,0.5978900062077661},{0.6079746262449569,0.5904137837209821,0.6140694737501032},{0.5897050882143063,0.6024131684273561,0.6212822459480813},{0.5978096888536524,0.6045137326091811,0.5872220021476077},{0.5919537097588187,0.5999334298401237,0.5931166935377409},{0.5945647875062369,0.5849963916806026,0.5950916074654382},{0.6088684040040332,0.5844096872195742,0.5998298335031309},{0.5987959453710199,0.5907990320252082,0.6120620053416871},{0.6104536363717536,0.6059329149360491,0.5995018806607364}};
                // {0.6077049930996429,0.6077049930996429,0.6077049930996429},{0.5911618817816682,0.5911618817816682,0.5911618817816682},{0.5982867199332335,0.5982867199332335,0.5982867199332335},{0.605950938928775,0.605950938928775,0.605950938928775},{0.6165454308890274,0.6165454308890274,0.6165454308890274},{0.5937022166689185,0.5937022166689185,0.5937022166689185},{0.5990321836737337,0.5990321836737337,0.5990321836737337},{0.5871030592614939,0.5871030592614939,0.5871030592614939},{0.5930022282063667,0.5930022282063667,0.5930022282063667},{0.6130757252683101,0.6130757252683101,0.6130757252683101},{0.5978220475471928,0.5978220475471928,0.5978220475471928},{0.5872872348637117,0.5872872348637117,0.5872872348637117},{0.5880892314515322,0.5880892314515322,0.5880892314515322},{0.6070730159438522,0.6070730159438522,0.6070730159438522},{0.5894143782658511,0.5894143782658511,0.5894143782658511},{0.599005391327391,0.599005391327391,0.599005391327391},{0.6036133597799735,0.6036133597799735,0.6036133597799735},{0.6072065062391973,0.6072065062391973,0.6072065062391973},{0.5996041984673666,0.5996041984673666,0.5996041984673666},{0.6118012000166696,0.6118012000166696,0.6118012000166696},{0.5939191739484727,0.5939191739484727,0.5939191739484727},{0.5886750065063125,0.5886750065063125,0.5886750065063125},{0.5997426684771702,0.5997426684771702,0.5997426684771702},{0.6102334863401919,0.6102334863401919,0.6102334863401919},{0.5912972333278679,0.5912972333278679,0.5912972333278679},{0.6025604243740265,0.6025604243740265,0.6025604243740265},{0.6219972918131564,0.6219972918131564,0.6219972918131564},{0.5923896403159432,0.5923896403159432,0.5923896403159432},{0.6027579545288441,0.6027579545288441,0.6027579545288441},{0.5919086122601278,0.5919086122601278,0.5919086122601278},{0.5893599381995716,0.5893599381995716,0.5893599381995716},{0.5810214653023501,0.5810214653023501,0.5810214653023501},{0.589016806862104,0.589016806862104,0.589016806862104},{0.5911380139516503,0.5911380139516503,0.5911380139516503},{0.5970084355685829,0.5970084355685829,0.5970084355685829},{0.5993451823616759,0.5993451823616759,0.5993451823616759},{0.6033988664617769,0.6033988664617769,0.6033988664617769},{0.6096485616936191,0.6096485616936191,0.6096485616936191},{0.6025352417947997,0.6025352417947997,0.6025352417947997},{0.5897520322856289,0.5897520322856289,0.5897520322856289}
                char* data_str = serialize(kirat_data, 60);
                printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 2) {
                double kirat_data[120][3] = {{0.5968148553076759,0.6015018276624374,0.6065827190667042},{0.598881144072725,0.6133578910391299,0.6034579897467162},{0.6009934986437997,0.5957503412480062,0.611088659108662},{0.5912092915889937,0.5971608788238281,0.5982932656586835},{0.5798747789516384,0.6000264288347634,0.598726384492252},{0.5910809872260083,0.6109381175806798,0.596782977994628},{0.6015001443328322,0.5956149243860586,0.5977989666458244},{0.5878612536775365,0.5851555623005972,0.6025194267393577},{0.6052325957727462,0.591415994686265,0.6092801628262535},{0.6047712601043101,0.5966926965586997,0.6188503065794172},{0.6127135410532561,0.5829157070403259,0.6085026067887057},{0.5921370183450978,0.6024097838803935,0.6082733872219424},{0.605753210630075,0.6337119202150434,0.5956895219219345},{0.5944283369490154,0.5825061533140543,0.5940345927353625},{0.6083063016100781,0.6020744416461558,0.6108853717408078},{0.6030133046377939,0.609899872264843,0.6037038042653013},{0.6227656579058981,0.5907196079574852,0.5899980755429861},{0.5908559981419248,0.5951014873958461,0.5985329536260774},{0.6042682499720323,0.5923972393590934,0.6057193037865638},{0.6114077056321923,0.6063074592491855,0.6079814533296838},{0.6034764224438244,0.6053797144137755,0.5868055215626397},{0.6089606012059792,0.6180559263719251,0.6035410733087656},{0.6060102193502194,0.5919341191312186,0.5985147633297699},{0.5902536427831587,0.5907077560095643,0.6049988055514657},{0.5901517850555004,0.6021762221756547,0.5841872287489526},{0.6087236809212418,0.5904995160478378,0.5938466200319178},{0.6239129007039268,0.5805185918242797,0.6165965002906596},{0.6024191578244917,0.5938703274561553,0.6088666856423223},{0.6000244034607783,0.5984926328647177,0.6121209770626072},{0.6098505994207326,0.5897735380844836,0.6021521197706196},{0.5835102072467295,0.6073559107690213,0.613726599024493},{0.5975947362169399,0.5988342163668592,0.58577120057237},{0.5930604243320995,0.6166825766204687,0.6029900546009389},{0.5926928621993626,0.5947684137790197,0.5936665206873667},{0.5955895142996717,0.6050560518052115,0.6006611424119699},{0.625924443998118,0.5761895244920823,0.600958475482053},{0.6033889570975881,0.6066602071531695,0.6000733905835389},{0.5920407098741188,0.6009690417429601,0.6173547588306046},{0.6101818854183041,0.6008129956852131,0.5981724844532096},{0.5904621312008184,0.6182753809896642,0.5950247555156641},{0.6045810236378967,0.600005407027956,0.6121412235453294},{0.6041181993024853,0.5844556663083218,0.5886962847160926},{0.6167770229824001,0.5992313157127571,0.6052224835870631},{0.5981677747432013,0.6097542607863585,0.5942102026259315},{0.5875390846647336,0.5988677821563407,0.5692466676306696},{0.5976854669447361,0.6158186172286596,0.6242085726972568},{0.6054617213756534,0.5970968479693933,0.6057984622334324},{0.5907251479120642,0.6089404936075054,0.6061574557190151},{0.6060745187534639,0.6070700113805437,0.6007786475390101},{0.6021814822583685,0.6058710450483538,0.5986589543476374},{0.609275574328915,0.5963370202436361,0.60791485831359},{0.5934575506910149,0.6063487803999106,0.5747792573611391},{0.585764628813032,0.597991120456355,0.6030564802351951},{0.5766715617335211,0.5871656413300449,0.6265735211512407},{0.6061730335172566,0.5940009751906052,0.5806024171546239},{0.5905101521147079,0.602652181057029,0.5972974179614251},{0.598333981876061,0.5885175042854406,0.6096003779402484},{0.6145748986652657,0.595973409113185,0.603874531483803},{0.6042880512592612,0.5924101566973629,0.6046115559345717},{0.588296449131413,0.6007941563336214,0.6076597761630477},{0.5911227156076904,0.5787919282293075,0.6061539071589287},{0.5961521346497314,0.6069820510902673,0.5994751788733206},{0.591832609279179,0.6012662107307415,0.5784584346051677},{0.5992670923000504,0.6236893685778349,0.6193603921938289},{0.597086151946617,0.6021270584639575,0.5958104606486088},{0.5845843503143006,0.6193781146518169,0.5948121916706214},{0.5879249910846146,0.5870550600391239,0.6102553838974466},{0.5966927685180653,0.6061691839676598,0.59073955838116},{0.5865552130670567,0.6217754558173294,0.6051764509722488},{0.6127223608196304,0.6000866122777074,0.5973665197720427},{0.6145799774347059,0.6018246651306056,0.6043416229735558},{0.6052805187917631,0.6161312874393542,0.6105148850478607},{0.6057906968800186,0.6047728268181289,0.6047991494405262},{0.5873902953561458,0.5835252803811593,0.6057453844171078},{0.6134476427694678,0.6123949814019752,0.6011729404029917},{0.6149971290799786,0.6100524164723297,0.6058082178262063},{0.5939320478828227,0.601060420984968,0.5969967391600187},{0.6146749246426463,0.6052772356023811,0.5979455940178247},{0.6035062016543273,0.5924232493464444,0.5974369054738257},{0.6080223159779524,0.5853381079708849,0.6203513674424794},{0.607565481723308,0.5963478484251576,0.6101551941515315},{0.6179844816024632,0.6056190582902135,0.5919106933784198},{0.5849561811116184,0.5936633468817999,0.5933304691320157},{0.596502542850673,0.6129368142245362,0.6066413511734758},{0.585011648848971,0.5984777773026367,0.5936622873973093},{0.6028048712583787,0.5974196132003059,0.5943671710226991},{0.5951081774236507,0.6019592837379341,0.6115368665943995},{0.6049246283786945,0.6130474442088143,0.606469454304725},{0.5839755500342466,0.5977279639400074,0.6065569490973914},{0.598673577407885,0.5911154730333147,0.5850267833894651},{0.5972613162696616,0.5846055196770525,0.5845616485201501},{0.6000987782571248,0.6012448238393268,0.6080374892491144},{0.5984953647180897,0.6172810739351381,0.5989922114848331},{0.5963244438787321,0.6030256113480761,0.5898825378806335},{0.6193436996459553,0.6145915452356508,0.5931549744592605},{0.6084949991952241,0.5940851616593056,0.603224739949258},{0.5895612176775434,0.6054483368165104,0.5883912215213747},{0.6029113260533242,0.6208941039331993,0.6102137972054705},{0.5916855239995369,0.5845947382927004,0.5940751179296309},{0.582557509403684,0.5957008112580285,0.5970502734880107},{0.5952105546200211,0.6242383507661554,0.6151116652664269},{0.5865529774328687,0.6000352579985186,0.6075307457658475},{0.6071003381858245,0.590475963669814,0.6083461826757737},{0.5925750767636612,0.590044693938228,0.6113673151010269},{0.5855576079413186,0.5738537623695321,0.6134462861454005},{0.594417626924993,0.5954093613410547,0.5919698994262944},{0.6087617874065715,0.6051680456024626,0.5939729105730426},{0.587417003845449,0.6161987792564269,0.5904957405429387},{0.6011391727214755,0.5884318639364411,0.5961713315801512},{0.5812259224693604,0.6026766566934008,0.5992892844302531},{0.6101047048568632,0.5862879202474232,0.5977265567760977},{0.60276982875283,0.5856255621367518,0.5869597567273562},{0.5912890812790125,0.603808025472347,0.587256575500947},{0.5922661960790144,0.5942025506947949,0.5943215101580301},{0.6052154187812108,0.6043166783189053,0.5947074280240006},{0.5922635366768434,0.596543766641684,0.6104630678517131},{0.6122956057389981,0.5959292425842475,0.5828519813965574},{0.5832810884398202,0.6034691801681794,0.599739814773657},{0.6029911854096844,0.5955254857794982,0.6137859541186597},{0.5965997273911692,0.6044870732195855,0.6172050599934095}};
                // {0.6077049930996429,0.6077049930996429,0.6077049930996429},{0.5911618817816682,0.5911618817816682,0.5911618817816682},{0.5982867199332335,0.5982867199332335,0.5982867199332335},{0.605950938928775,0.605950938928775,0.605950938928775},{0.6165454308890274,0.6165454308890274,0.6165454308890274},{0.5937022166689185,0.5937022166689185,0.5937022166689185},{0.5990321836737337,0.5990321836737337,0.5990321836737337},{0.5871030592614939,0.5871030592614939,0.5871030592614939},{0.5930022282063667,0.5930022282063667,0.5930022282063667},{0.6130757252683101,0.6130757252683101,0.6130757252683101},{0.5978220475471928,0.5978220475471928,0.5978220475471928},{0.5872872348637117,0.5872872348637117,0.5872872348637117},{0.5880892314515322,0.5880892314515322,0.5880892314515322},{0.6070730159438522,0.6070730159438522,0.6070730159438522},{0.5894143782658511,0.5894143782658511,0.5894143782658511},{0.599005391327391,0.599005391327391,0.599005391327391},{0.6036133597799735,0.6036133597799735,0.6036133597799735},{0.6072065062391973,0.6072065062391973,0.6072065062391973},{0.5996041984673666,0.5996041984673666,0.5996041984673666},{0.6118012000166696,0.6118012000166696,0.6118012000166696},{0.5939191739484727,0.5939191739484727,0.5939191739484727},{0.5886750065063125,0.5886750065063125,0.5886750065063125},{0.5997426684771702,0.5997426684771702,0.5997426684771702},{0.6102334863401919,0.6102334863401919,0.6102334863401919},{0.5912972333278679,0.5912972333278679,0.5912972333278679},{0.6025604243740265,0.6025604243740265,0.6025604243740265},{0.6219972918131564,0.6219972918131564,0.6219972918131564},{0.5923896403159432,0.5923896403159432,0.5923896403159432},{0.6027579545288441,0.6027579545288441,0.6027579545288441},{0.5919086122601278,0.5919086122601278,0.5919086122601278},{0.5893599381995716,0.5893599381995716,0.5893599381995716},{0.5810214653023501,0.5810214653023501,0.5810214653023501},{0.589016806862104,0.589016806862104,0.589016806862104},{0.5911380139516503,0.5911380139516503,0.5911380139516503},{0.5970084355685829,0.5970084355685829,0.5970084355685829},{0.5993451823616759,0.5993451823616759,0.5993451823616759},{0.6033988664617769,0.6033988664617769,0.6033988664617769},{0.6096485616936191,0.6096485616936191,0.6096485616936191},{0.6025352417947997,0.6025352417947997,0.6025352417947997},{0.5897520322856289,0.5897520322856289,0.5897520322856289}
                char* data_str = serialize(kirat_data, 120);
                printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 3) {
                double kirat_data[240][3] = {{0.6072376057112315,0.5973902900956234,0.6039979665667176},{0.5897511838145757,0.6106807140708187,0.6097795426913016},{0.6093061022142552,0.6156014067045225,0.5856507483639931},{0.5957587736602403,0.587468042511388,0.5975256374437553},{0.6006410977522463,0.6198859363857973,0.5997422268448263},{0.6233641445499125,0.5986424639593072,0.5982522976745825},{0.6061288272867431,0.6088192607547623,0.5960572285061202},{0.5991297797512805,0.596278435894367,0.5956948794162581},{0.5842153102607497,0.5960621333527384,0.6054290381664968},{0.6080905519733429,0.609425199279175,0.5971790307623924},{0.5770758251731717,0.6144948274493921,0.6077300557448072},{0.5919460319886348,0.5926858669415157,0.5883107729594963},{0.5970230463309584,0.5991467892289447,0.5994538236441712},{0.5830309530061871,0.5791614740069374,0.5971089073837433},{0.6086625539908717,0.5971907686005895,0.6161958024583373},{0.5938382449572265,0.6034487967657024,0.6095878054515937},{0.6009721221429006,0.5829621221077017,0.5872102228133858},{0.6077829770069978,0.6060648565608893,0.5921764518214662},{0.584544471943157,0.5919384289681217,0.589271317783309},{0.5966926608698597,0.6044967183293264,0.6008258249379402},{0.5850586937261353,0.5971576702309552,0.6113397743847535},{0.5943888077002092,0.5965948546324688,0.5776447320278744},{0.6048656580353245,0.5997632283417482,0.5887755213576241},{0.6191272777500556,0.5980344390747271,0.5936235625788153},{0.6015561251062806,0.6028484498834877,0.5917778090631381},{0.596790598861802,0.6005619986236065,0.5933711688188759},{0.6216097455898181,0.5947473471653822,0.5959218347432025},{0.6000752143333887,0.5962984418768743,0.597649507536233},{0.5888805426609831,0.5922125294735288,0.6171997607828652},{0.5923578033260923,0.6014114133778257,0.5963134947375704},{0.6089653311683362,0.5981629399173933,0.6014261948953986},{0.6067455209980931,0.6109439593770776,0.6176305872846898},{0.6081697004166788,0.6128316934242038,0.6088934083722839},{0.6059569580459014,0.6001285652268997,0.5983012156808619},{0.5987186364841942,0.6045853098164728,0.6009887903631007},{0.5968989422096553,0.5913096552677906,0.6065243777499383},{0.5984652490521287,0.58374570792702,0.608218794725986},{0.5981623392648577,0.6037711245327018,0.6148844900978412},{0.5833379905832248,0.6047550818659893,0.606607120160509},{0.6094093280997926,0.5968636780276568,0.6055633034790162},{0.5920716466709057,0.6101101795660728,0.5972783858160535},{0.6198890540397914,0.5752099270379819,0.6026609178475767},{0.5946905330868084,0.5911212892651201,0.5961499536331479},{0.5993412909673578,0.6011757900903695,0.5985719052140944},{0.6165759968669727,0.6053335868031481,0.6149186707264315},{0.6158148661232514,0.6183675153241335,0.5827073120696445},{0.5990366160822826,0.5900774475926759,0.6086903987381148},{0.6014326479872151,0.6154430702437247,0.589614844773157},{0.5980919127478961,0.6077593070198076,0.596098239087177},{0.5942109781140297,0.5974040850977163,0.6051488170238088},{0.5996537353533514,0.600934090027242,0.592591634170932},{0.6061462236960848,0.5900103399591876,0.5935419816250738},{0.5994699892898617,0.6135928812072258,0.6241288682129522},{0.6022262706508914,0.6346636759860826,0.6024663604307814},{0.6041263921477749,0.6071399677479961,0.6020164888129141},{0.585154219567159,0.6075188701188495,0.598366243023973},{0.6019755835067667,0.5852312044428568,0.5866950834268816},{0.6102709956256472,0.6039775285998099,0.6067770800713861},{0.6117440356326618,0.601120985057509,0.5879932111596037},{0.5912047774220591,0.6069718331497785,0.6024040328483226},{0.5866473432596793,0.600145995640211,0.6001039779038383},{0.6011086722570451,0.5986024177060286,0.6199173075313429},{0.6042429744018065,0.5923441781066339,0.60744108998616},{0.5852546728907375,0.6103849560491033,0.592750375175113},{0.5893305192908755,0.6068243824644042,0.5870632332480391},{0.5881705875254858,0.6117861044305903,0.6054266107715393},{0.5980422112588207,0.5832377660969771,0.6004973809978607},{0.6120046306686533,0.6003480338892881,0.5833622915462788},{0.6189886190737826,0.6166759283145882,0.6079761009291513},{0.5986275957586177,0.600022312289886,0.584138324146745},{0.5890137788990935,0.5850896974686149,0.600419088257304},{0.590001542726285,0.602113190919765,0.6035006505633255},{0.6013384629423291,0.5958841331828904,0.5986027513111472},{0.5852990455798663,0.59625375665258,0.5899696738139467},{0.605802947826155,0.5976078187882687,0.6070374515296437},{0.6125809257877267,0.613781363731131,0.6032525578527308},{0.5965050901034724,0.5901069405340112,0.6024296837471165},{0.5957554394463596,0.6111684448299131,0.6013775507590194},{0.6148919758627105,0.6042854281029092,0.5939207898776083},{0.5956115153402506,0.6211897799775632,0.5947812980708926},{0.5950239810889532,0.6088282396233021,0.6073917343881502},{0.6049037153875556,0.59466962275481,0.5930374080637726},{0.6008967104355338,0.5947718129704139,0.5837220596327845},{0.6157393019622138,0.5948945439485323,0.623670555876161},{0.595266619677319,0.5884442432793299,0.5768806433214962},{0.6003808037600171,0.6068093602999072,0.6101351697901318},{0.593380733963004,0.5872571258520953,0.608123072172195},{0.5896505848413921,0.5964587668082328,0.6069661841126933},{0.6085753209369983,0.5978942492228582,0.5861100191446846},{0.5972901984655672,0.5884975026237154,0.5934696860966256},{0.5852732551370368,0.5909923961197994,0.5901617970335007},{0.6017344577405376,0.6047277323891254,0.601895132758887},{0.6009353421746213,0.605515399618082,0.6215446579818976},{0.612284038718641,0.6020299604505355,0.6125006743135809},{0.5950134212379918,0.5930995051022111,0.595251712703154},{0.5872612729699926,0.6062487309787282,0.6027928488742897},{0.6020609326270719,0.5856946690101795,0.6048585788363118},{0.61151339646134,0.5983337879556266,0.589322239134521},{0.5835378440201215,0.5779617271980451,0.5801483656636698},{0.5941932502807226,0.6243262574747752,0.5985589126963539},{0.5986555761321842,0.6190779754389729,0.5975844410281775},{0.5867633612635335,0.6153881669639807,0.6114438068958339},{0.6078431638800956,0.601510573168388,0.5999753522408764},{0.5996757797354257,0.5957472419227606,0.6006825713167094},{0.6008465587102217,0.5943557191332396,0.6017496598908959},{0.6009484661497729,0.6161719487148654,0.582574512204962},{0.5805755131860774,0.6130327775293407,0.6060153457673914},{0.607351827431489,0.6199917394792356,0.6046933045259281},{0.613044773555452,0.6082613350640483,0.6097847427392686},{0.6065871719299684,0.5976908434648214,0.5810951179572348},{0.5972596250652098,0.6003669915477648,0.5979969228374528},{0.5890025567440955,0.5867068187822625,0.5918850453069546},{0.599480500203491,0.6042174717623047,0.6062337066532536},{0.6034252509034189,0.5792645109516222,0.6010923382197141},{0.5833745483265881,0.6229626080320481,0.6204129352562388},{0.6003583686267613,0.5941921889679279,0.5985325430599533},{0.6095843058785413,0.5851407496866474,0.5979926936989292},{0.5941823245732589,0.5919258589696563,0.6082226012250918},{0.6015121785205927,0.5988802718255715,0.6116000629917977},{0.6099873254005981,0.5915400381064889,0.6022511496741804},{0.5960159592757498,0.6151877545258474,0.6101666862764172},{0.5971379615035752,0.5927644102099175,0.6069379401593079},{0.610086568223584,0.5989494286462924,0.6187434474600253},{0.6008970071367581,0.61540449943325,0.5875391247237263},{0.5992663075110419,0.5803925144801645,0.6184902178876847},{0.5877641049281032,0.583260426915324,0.6078442154884975},{0.6007402295189888,0.5957454435000835,0.5943524365174143},{0.6027880572269227,0.5815230252114821,0.5971266598421102},{0.5971512794755238,0.5948371120617507,0.5969287410945362},{0.5910851354126386,0.5955308449383745,0.6058527014598285},{0.6155418145663472,0.5978046206230963,0.6048919619651332},{0.6003282948717287,0.5915395214587741,0.5796808951927006},{0.6080309773684526,0.5862409271954819,0.6085951949732066},{0.5828905924768286,0.6073871490087726,0.6101088294989688},{0.602887821269272,0.6199699179018516,0.6085600933285772},{0.5950517635212234,0.59713141523064,0.5967880889507944},{0.5893924852264415,0.609029111329596,0.5805812672767153},{0.5939512614508959,0.6003053465852497,0.6115480748997348},{0.6006673824897683,0.6029109278616099,0.5990773226440508},{0.6179167094189058,0.6072130211375562,0.6139396822601375},{0.593920664408445,0.5967652658872789,0.6026443977005378},{0.5937579842245106,0.6049282494966602,0.5826543139424627},{0.6024432604813302,0.6006664055515655,0.5837870165635841},{0.6166390675377168,0.6023974669749242,0.5985491191388939},{0.5825750920202827,0.6164357129415795,0.6025468134389527},{0.6073669743193795,0.6125827948422187,0.6173423779622025},{0.5820390649307758,0.6071855297373958,0.6025105500801423},{0.5885506089762866,0.6039622308289575,0.6032527894157225},{0.6021644934650436,0.6064962226616202,0.5982754890276621},{0.5990076267306738,0.5934686762635939,0.6255611226773383},{0.6082173588622167,0.6027012013082474,0.5922646608887008},{0.5875965055050965,0.6060990260109994,0.5858914312283579},{0.5803756841545659,0.6050712937715749,0.5941424089052463},{0.5817242763691539,0.6172290083054968,0.5998094476209063},{0.5924413168202366,0.6004793249374556,0.5787057301403604},{0.607458303684257,0.6052152629345231,0.6021191310149916},{0.6107761848852946,0.5918338388204656,0.5976823881835577},{0.5854061105689975,0.5993986584149021,0.6093178594187851},{0.5955539005131206,0.6076327273724438,0.6058472346696376},{0.5913243290939963,0.5885714538198917,0.5864223653861587},{0.593115961131707,0.6131909876204235,0.6049660221811963},{0.5991628065519918,0.600803771652743,0.5980652605675078},{0.593481069456938,0.6063709561130399,0.6069407705123785},{0.6095008646109127,0.6126174215122313,0.5927661624279037},{0.5854129830389304,0.5858727275722685,0.5865786966473183},{0.6067121741286694,0.6008315957121949,0.5987913425345985},{0.5933089708669955,0.6194112846761737,0.601125445036847},{0.5927666413324364,0.5889914229708485,0.6138210646703406},{0.5938040205159852,0.6230209837610173,0.5869071857634927},{0.596264614130553,0.587361230577057,0.5965317579658573},{0.606904274518233,0.6009463389617604,0.6061077550577603},{0.611003757226662,0.6035466769023451,0.5835414750623489},{0.6110842550579512,0.6010028014155883,0.6073758260039173},{0.5961526028920158,0.5867458066459109,0.6079568408048338},{0.6049572644009077,0.6083395738980347,0.5713375933631295},{0.6150258856821017,0.6089609172975048,0.6253285871241364},{0.6029415747726892,0.6054957877818764,0.5967325848932776},{0.5942779925913336,0.588958667375391,0.5960405214331277},{0.6003933675970022,0.6067139735306577,0.6018313051034615},{0.601002749434888,0.5994479448447937,0.5991123378688469},{0.6144498280935579,0.5991769426364287,0.6020210094207303},{0.5934979405434831,0.5953925427349847,0.6089903917393776},{0.6032943855655122,0.6113383498494499,0.5912459305321285},{0.6009763672688326,0.5965482597395927,0.6174742756623656},{0.5947259683977071,0.6116185487925315,0.6072020236997225},{0.5863031088119317,0.5765603562485124,0.6025021598618787},{0.5870707971312498,0.5921221397788224,0.5991633269258889},{0.5973811960940622,0.5911637037012799,0.5982561639962873},{0.6084535962243556,0.6083341499947905,0.6240755123738463},{0.6032171437104342,0.6092506248699625,0.6065068769186965},{0.6066399173592136,0.5892231202897716,0.5984809943565228},{0.5992525506649354,0.6191617368016731,0.60280422443062},{0.6018607628021613,0.5918480914197384,0.5991046621987152},{0.6034390430944961,0.6013536333278466,0.6049227056035343},{0.5970946700126338,0.603689723464901,0.6131679340342848},{0.6034853902578609,0.600427639306337,0.601177711027213},{0.6122867770594708,0.5992263672539581,0.5882869735631154},{0.5954944387362591,0.5939061579002683,0.595222357297436},{0.6097269006304488,0.5898285131725067,0.6104122250139961},{0.6060141268850368,0.6113880620345898,0.5985360163146719},{0.6111887646612075,0.6074134261071423,0.605643884904365},{0.6058729073720736,0.6072298837408294,0.5923172222608112},{0.6108943074211526,0.6033423822706675,0.5886259044681477},{0.5799753034391317,0.6103724977815024,0.6108498676716403},{0.6008358901787259,0.6016228720388707,0.5742154213857716},{0.5938510364573024,0.6172772108375881,0.6146462444964743},{0.5954618148244434,0.5940941288731767,0.5983126857046358},{0.590960834792644,0.5995839801513781,0.5992254569205703},{0.6277502800422019,0.5959921356537357,0.6063455197903376},{0.6023538435999778,0.6013919467242941,0.6100185483381877},{0.5909096329105862,0.6076440373119317,0.5995205622718457},{0.5822512766923288,0.5961794599557309,0.5876289376488572},{0.6020375373169156,0.6058030960604046,0.5977226052489072},{0.6175446526791706,0.5852299111503126,0.5777296340568738},{0.5801673685919586,0.5977747914664195,0.6057000183619393},{0.6162269486628611,0.608307905604807,0.6151548081937094},{0.6050381918746519,0.5976605815577499,0.6011586560387233},{0.5956879602697778,0.5889002429010637,0.6068544729471355},{0.5925773695971628,0.6021016108426698,0.6031858238049748},{0.5846847421305266,0.6092490584092141,0.613842541484309},{0.5867636577224195,0.6053380980922646,0.6025461199550772},{0.584487986751729,0.589442479133206,0.5859032579829837},{0.5940807454937854,0.5875263224509535,0.6045098692079494},{0.6089338318958187,0.5901281808864289,0.5977468056643395},{0.5842702160108274,0.6039647254815858,0.5951715926415604},{0.6297011582998109,0.6015203226543693,0.5948003434459189},{0.5945378533826243,0.6217699763336725,0.5948464433325484},{0.6043516086284944,0.5839502043088219,0.6021711723754778},{0.6008252589075586,0.6025975185606864,0.5872192140496879},{0.5826222744596861,0.5860712980774921,0.6131925543098516},{0.602455595997135,0.6062857000075502,0.6001773758357596},{0.5886969151383836,0.591598934354001,0.6027227373718644},{0.593990021408061,0.6019005149537927,0.5961409444870894},{0.5971776960140922,0.5998365270462495,0.6126075218452942},{0.6003780638013144,0.6141169279364044,0.6083760286456638},{0.6004252826098944,0.5879528291787169,0.5906231357025601},{0.597733748601403,0.6018511168747434,0.5915972410829381},{0.6051748969204361,0.5956733153306416,0.5991554939392401},{0.6070594267726809,0.5998722777639452,0.5948729735572538},{0.5934926079690345,0.6028653049367547,0.6154294696157043}};
                // {0.6077049930996429,0.6077049930996429,0.6077049930996429},{0.5911618817816682,0.5911618817816682,0.5911618817816682},{0.5982867199332335,0.5982867199332335,0.5982867199332335},{0.605950938928775,0.605950938928775,0.605950938928775},{0.6165454308890274,0.6165454308890274,0.6165454308890274},{0.5937022166689185,0.5937022166689185,0.5937022166689185},{0.5990321836737337,0.5990321836737337,0.5990321836737337},{0.5871030592614939,0.5871030592614939,0.5871030592614939},{0.5930022282063667,0.5930022282063667,0.5930022282063667},{0.6130757252683101,0.6130757252683101,0.6130757252683101},{0.5978220475471928,0.5978220475471928,0.5978220475471928},{0.5872872348637117,0.5872872348637117,0.5872872348637117},{0.5880892314515322,0.5880892314515322,0.5880892314515322},{0.6070730159438522,0.6070730159438522,0.6070730159438522},{0.5894143782658511,0.5894143782658511,0.5894143782658511},{0.599005391327391,0.599005391327391,0.599005391327391},{0.6036133597799735,0.6036133597799735,0.6036133597799735},{0.6072065062391973,0.6072065062391973,0.6072065062391973},{0.5996041984673666,0.5996041984673666,0.5996041984673666},{0.6118012000166696,0.6118012000166696,0.6118012000166696},{0.5939191739484727,0.5939191739484727,0.5939191739484727},{0.5886750065063125,0.5886750065063125,0.5886750065063125},{0.5997426684771702,0.5997426684771702,0.5997426684771702},{0.6102334863401919,0.6102334863401919,0.6102334863401919},{0.5912972333278679,0.5912972333278679,0.5912972333278679},{0.6025604243740265,0.6025604243740265,0.6025604243740265},{0.6219972918131564,0.6219972918131564,0.6219972918131564},{0.5923896403159432,0.5923896403159432,0.5923896403159432},{0.6027579545288441,0.6027579545288441,0.6027579545288441},{0.5919086122601278,0.5919086122601278,0.5919086122601278},{0.5893599381995716,0.5893599381995716,0.5893599381995716},{0.5810214653023501,0.5810214653023501,0.5810214653023501},{0.589016806862104,0.589016806862104,0.589016806862104},{0.5911380139516503,0.5911380139516503,0.5911380139516503},{0.5970084355685829,0.5970084355685829,0.5970084355685829},{0.5993451823616759,0.5993451823616759,0.5993451823616759},{0.6033988664617769,0.6033988664617769,0.6033988664617769},{0.6096485616936191,0.6096485616936191,0.6096485616936191},{0.6025352417947997,0.6025352417947997,0.6025352417947997},{0.5897520322856289,0.5897520322856289,0.5897520322856289}
                char* data_str = serialize(kirat_data, 240);
                printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 4) {
                int n = 480;
                double kirat_data[n][3] = {{0.6048732127329576,0.5840630762319088,0.6170005072605487},{0.5943080479441192,0.6086550176339505,0.603994620957204},{0.5943352745942742,0.603808847706192,0.5937271604418778},{0.5847341519154057,0.5911392753799286,0.6060797720238904},{0.5894560774748959,0.6054790271577432,0.5962597723212283},{0.5957762064003517,0.5925220824851478,0.5893313313933146},{0.5917241998969456,0.595520621953391,0.6085379233103929},{0.597133192817331,0.5952390360048003,0.6077181874179436},{0.5993902984502276,0.599579627218678,0.6076477729655753},{0.5892360757510903,0.5916204033738873,0.6012449689317103},{0.5991202390539547,0.5905982780389467,0.6016725159678694},{0.6101794292654085,0.5999111314607216,0.6053035108078434},{0.5929710285156001,0.589929150364234,0.6064549426652788},{0.5938997152831056,0.6040953034364778,0.5813062209600499},{0.6010630721399494,0.5990484269195943,0.6043885285698798},{0.5963163600085079,0.5995193870637228,0.592952926439145},{0.5885010803977506,0.6127189066809887,0.6096649116441913},{0.5856790045613856,0.5983354079530544,0.6009907594797916},{0.6073058716607328,0.5911496170559587,0.5945184441315073},{0.6144864514193987,0.5815222398162496,0.6137308517927401},{0.5959127954593982,0.5885419026803042,0.5876364888166592},{0.5953519686980824,0.5921123974679897,0.5748311929570645},{0.5997972255890853,0.5958046207704918,0.6177925484617747},{0.6095292342042723,0.5836361666502927,0.5896962548499718},{0.6022507650643686,0.6052420148190274,0.6006605969949532},{0.6113214185419967,0.5961220663323017,0.6024433129196608},{0.5999333858403658,0.5734027802101697,0.592500491347724},{0.5988388120021043,0.6238885825429322,0.6025986868098604},{0.5944718394538786,0.6061459078200755,0.6070076303349732},{0.5992133947708138,0.6116984481077656,0.5889082772712098},{0.5899141415254191,0.5992430415762511,0.5908840324366281},{0.5980616149893025,0.5933346219364677,0.6032014736613652},{0.6114004956746801,0.5972299060642662,0.5980560777551747},{0.6119343989865298,0.6054161704031207,0.6063440455451433},{0.5879943289848875,0.5926116479944001,0.5960593248694896},{0.6000843897822368,0.5855973008083057,0.6069614667353544},{0.5935036140053319,0.5866577428785354,0.6107801900544184},{0.6057079910840307,0.6017905153576775,0.6207460884056712},{0.6055253449120708,0.6128716946686862,0.5917318096221429},{0.6012674636324795,0.5973433220882901,0.5950189163485424},{0.5963026306081463,0.6074530743068213,0.6074384229830804},{0.6036031943724386,0.5944682372429222,0.590610395164076},{0.5841861861006873,0.5884407571442106,0.6271304297887903},{0.6033904764317839,0.5868667622468995,0.5909156053444483},{0.6168764045209171,0.5920186462678158,0.5865020997198568},{0.5852883348700565,0.5956940880082743,0.6030678479849635},{0.6068841939208174,0.5931968457916444,0.5981321925817729},{0.5965744229120242,0.5864287881093655,0.598207986084641},{0.6021157785354548,0.6144162818145327,0.602409089637559},{0.584395582061329,0.6044461336293484,0.6137500876977289},{0.6016469272718177,0.6166689333362526,0.6049376534722177},{0.6011445205769445,0.5939918225973262,0.5880693245411454},{0.6138277056162924,0.5901501633155398,0.6061413534947102},{0.6003211689511082,0.6005452724134915,0.6090339508248759},{0.5881455176108773,0.6178963747103403,0.597202702651303},{0.6077904909162359,0.5854346059809766,0.5949666052180469},{0.6076341896527448,0.6080854378048285,0.6012538666873823},{0.581090196922032,0.6207530096065621,0.591763011162175},{0.6102219843810356,0.6109018187566103,0.6029477264362588},{0.5998892211931128,0.6072180473305032,0.5983149297418582},{0.5868914488632947,0.619626742679279,0.6141401579987483},{0.6107493954751124,0.6110870533120506,0.604078793204166},{0.5888378615979512,0.6032454975732782,0.6129993013891635},{0.6140459973239875,0.5966937413929813,0.6090802105685725},{0.5934235988392479,0.6035966575553632,0.5923947158713477},{0.5984254162499933,0.5904959785415895,0.604201228138896},{0.5991903631478046,0.5886438859622275,0.6102467275185387},{0.6075334372555002,0.5995562414692956,0.5889336732996764},{0.6193200722811804,0.5914380491471246,0.6028269522875623},{0.594007681850179,0.6073780831755069,0.5978115434017066},{0.5905491777068657,0.6039444143862148,0.5977192769097702},{0.6049154802180612,0.5985738558909005,0.617764741804392},{0.5883201478802016,0.5899779655295551,0.5912994091970238},{0.607317638947487,0.6020152483049716,0.5919522045078403},{0.6219668489059028,0.5871452214758976,0.6278636685234288},{0.6229408730707824,0.5993361361813198,0.5762495081878751},{0.5961747546328597,0.6035655020622163,0.5981456653841816},{0.600548955127824,0.5985322616570263,0.6021483148671484},{0.5912067575306071,0.6107249017648644,0.5827575524657039},{0.6005291689131402,0.6011405415872021,0.6168508779905605},{0.5976105037915614,0.6182754182627274,0.6066036669928435},{0.61374485617659,0.60505656509963,0.6125293597184707},{0.6061297475936162,0.5914488529960866,0.5931351461501064},{0.5955189025154521,0.5996877582227145,0.6047726481293041},{0.5965213840905724,0.6117549145487932,0.6016582573546786},{0.5963519090706857,0.6076278025519669,0.6041698418180478},{0.6047862889833576,0.593432824445307,0.5800468462456708},{0.6086565934959802,0.5849611035024483,0.5838497140833502},{0.5928803695058706,0.5889891360090221,0.6119507237981597},{0.5984386077681976,0.5931570697097784,0.5804583865858985},{0.602129702336757,0.6102528758988894,0.6094485628278701},{0.5926721524779177,0.5921024162897781,0.5971743848209561},{0.6097064710911791,0.5991543283667535,0.5959731861351913},{0.5902338123500204,0.606585305726272,0.5951031580418294},{0.5882185936979478,0.5964627804460649,0.5935342950224648},{0.60525263015982,0.6060140086089002,0.6182632218588979},{0.6069745561763885,0.6003212783665484,0.6131680096828928},{0.601057626646374,0.5954363443869212,0.6092097094595664},{0.5968611638636621,0.6160439165762328,0.5979183494639877},{0.5812407727478697,0.5872942142922873,0.6047242367830431},{0.6071919302046427,0.5832202039401522,0.5906618422921993},{0.6084611834985084,0.6165156545845261,0.5925686569497806},{0.6094214096225633,0.6022645380269299,0.606353286717555},{0.5921435762502951,0.594793882473415,0.6080785584654739},{0.6100243206866939,0.6009797707851021,0.6084191399497493},{0.5957203964408812,0.5996633397903061,0.5973039618642869},{0.5954662504330148,0.6012557881778959,0.5981191329686336},{0.6026104147932917,0.593997669165419,0.5924588873901762},{0.612497107306886,0.6133257921941087,0.6063983466766313},{0.6043879962452082,0.6057390262652379,0.5998120355364994},{0.5831751254995932,0.6026389172866919,0.6085165737374134},{0.5943749856653503,0.5904567195972746,0.588431463128666},{0.6006238113619886,0.5927134158564402,0.6072730595430795},{0.606560362019452,0.6104248345099343,0.6086960652984323},{0.5844182120197151,0.6014416722874618,0.5794907285947833},{0.6055474806138952,0.6091803110775356,0.6185099061464859},{0.5863727002332338,0.5998483356574535,0.6049124653069133},{0.5842349176534454,0.5931458359443618,0.597886279706342},{0.5860742142596137,0.5989662693978374,0.6091621405750887},{0.6037964549172893,0.5892698196528166,0.6004147137919493},{0.6092403236460668,0.5922973750947855,0.6063721844810128},{0.603312291951374,0.5828515884209097,0.5871940318717151},{0.5971449898051349,0.592881966203626,0.5947003793090564},{0.6158534506988966,0.588111461762085,0.6151806067907418},{0.5932485978073446,0.5984859896826453,0.6115779537900711},{0.5945575423421066,0.5954793937771374,0.6078613214563365},{0.6012282129999963,0.607517575633426,0.6106621838497464},{0.5951170418672108,0.5795568481697015,0.5923664573332161},{0.5734398955219973,0.5894693850614889,0.5934386137627576},{0.5902599481052989,0.5804068947031694,0.5943814282017145},{0.5776494308350358,0.610345648183025,0.5949569157642544},{0.6039131601528969,0.6058774402757835,0.5999677899117812},{0.6107632124108541,0.5825431782860853,0.5999001423901664},{0.5941468249397281,0.5818404611137203,0.5990205435737491},{0.6048575917382898,0.5886266173583544,0.6199302873586168},{0.6012338527283507,0.6014114268439646,0.6004485949351095},{0.594993703999093,0.5833811337169531,0.592351641346758},{0.600287031171252,0.606625093597586,0.6090902388741618},{0.6033989322624779,0.6105413700777848,0.6000622053913617},{0.6056949253014381,0.6004356578979256,0.5934957827419247},{0.5986918378714067,0.6040486112249516,0.6009929938631322},{0.6038848825327042,0.5980546375889028,0.6135111950356558},{0.5957811789791861,0.6011421421595703,0.5951981645885753},{0.6009280533954495,0.5968030007561866,0.5959198605082295},{0.5966844380583953,0.5960646126554651,0.6140205696193559},{0.5832339798105785,0.5906647569370521,0.5989912361787408},{0.6019453261456577,0.5973821297846578,0.5982063190846346},{0.5876186620612475,0.607302533184174,0.5923961784483607},{0.5942030908409909,0.5929617699616029,0.6091511621053975},{0.5917932195729262,0.5820971740309826,0.5939520341645605},{0.5929042900957532,0.6129490678785569,0.6102141030483346},{0.5949350407787969,0.5842317531479073,0.5853242047201235},{0.5964891009262432,0.5966436665863195,0.6226326781086318},{0.6076482309728266,0.6146164790794328,0.6027135280707236},{0.5816032585014141,0.5905765521549378,0.5894676646518555},{0.5975947518472288,0.5755741245434335,0.6121233996203018},{0.5880381510102799,0.5847009871978672,0.6005978010497149},{0.6015311299860072,0.5972650894984278,0.6011860988539419},{0.596053916113502,0.5996105087630219,0.6013126527982378},{0.6077418068755427,0.5945907463004373,0.6008887138566563},{0.6079662212853457,0.5950415731507934,0.5934569714931962},{0.6051854904468486,0.6065120658117082,0.5936803237037473},{0.5930541098343289,0.61106012123487,0.5989332451550139},{0.6191157949583174,0.5912072937972508,0.6109416450610594},{0.6033621301318789,0.6087593127702362,0.591562708030415},{0.6044575691845104,0.6040162885442042,0.5797194230944693},{0.5797253948919296,0.6093259466902339,0.5994096580276388},{0.6017760236398438,0.5957036974551827,0.6111931945813004},{0.6021430548504667,0.5995360444222774,0.6060600900553277},{0.600409644009961,0.5852308058336685,0.5990331925484114},{0.6161289280163544,0.5997369431780832,0.5801874547403305},{0.6107528933438028,0.5912209743172872,0.6045863348848592},{0.5956236440455439,0.5915698766992664,0.6115503267312392},{0.5917879828785344,0.593848257010805,0.599457353078731},{0.5977522326055836,0.596124553378273,0.5990521646296072},{0.6094393176480575,0.6019154661806417,0.5847628990069692},{0.6130368299884693,0.6045696356008584,0.604422112304878},{0.6042100435335126,0.6049278746445992,0.5867506641318525},{0.6090155416454557,0.6021621317586794,0.6013270151906698},{0.6062746601144567,0.5821308671829881,0.602933129230044},{0.5988600612070127,0.5810278245093475,0.5978699887489516},{0.5965528374311904,0.5949631761735237,0.5772664631069918},{0.5890325841777692,0.6061760308783511,0.6200822925815807},{0.6065402334299573,0.5825967845052904,0.5907126083400888},{0.5903173971149122,0.6079657636168365,0.5938819133273093},{0.6001039579131874,0.6021039364611461,0.5812363865159457},{0.6066215262044499,0.5926961477684884,0.5951974810614904},{0.5948713246227243,0.6032709333861914,0.6047307036723323},{0.6007719417843655,0.6031288841962944,0.6008436402890773},{0.5992418570115372,0.5986821836799321,0.5982415304835803},{0.598887193152065,0.6046927188871294,0.591173230983733},{0.6062710654777744,0.5957892155639262,0.6168669387465368},{0.5929787571448508,0.5915543284936625,0.595149044480341},{0.5919093285143234,0.5865258815415548,0.608156731997144},{0.5935160192951019,0.622316225323424,0.6144755599499361},{0.6091948925397437,0.5748799319793881,0.5940283278087853},{0.5973069576168446,0.6016212749764457,0.6206748015807382},{0.6069360283111712,0.5958454564381227,0.5920661288959058},{0.5895262614734822,0.6077163962937283,0.5840499401030909},{0.6050864979517556,0.5856353973054861,0.5800722573112893},{0.5870400611269345,0.6002566372553605,0.5924685665288626},{0.5957675255827082,0.603296670512678,0.5907793930029224},{0.5976342868788982,0.603977747380263,0.594577569327638},{0.5969391359123545,0.588086132571841,0.5878595730066234},{0.5953108106427499,0.597488793931669,0.5980184807109973},{0.5966151923536465,0.6018158796917183,0.592272841329326},{0.5977809543404361,0.6001454523463481,0.6123399715847184},{0.5927648780847163,0.5921429512393686,0.5966984906293752},{0.6028952180986249,0.587704287693481,0.5911893293708415},{0.6040847812873579,0.6198949640117276,0.5863229290092052},{0.6078166193559171,0.5963049895096693,0.5946522086578795},{0.6164649793576058,0.6186421548351426,0.5873903337317266},{0.6087940647940682,0.5972009369161099,0.5964639699670872},{0.5935536491392399,0.6148890418801809,0.6019123024961454},{0.5957043289790497,0.596582209307942,0.6012861887046494},{0.6010514309931633,0.595939338187609,0.6033106757153369},{0.5837254494730485,0.6057749928946987,0.5917204025062006},{0.5938266073498787,0.5856961533059777,0.5894888458612764},{0.6157955268861494,0.6038484478958005,0.6054350178910232},{0.5987647099940933,0.6021818135280532,0.614540363505738},{0.5949311932387855,0.6035529236120598,0.5917636425870852},{0.5856259767040316,0.6031443716179987,0.5876466399094015},{0.5901546712120121,0.5955797197959358,0.584616701303797},{0.5988440357945665,0.5789370486983854,0.6092907417657406},{0.5972805400863237,0.5962004703520678,0.6141368160667972},{0.5990566880442175,0.5838973572439186,0.6027073942733726},{0.5855745962345685,0.6067769011446089,0.5983128052248639},{0.5982616700652812,0.5949691413175114,0.6026742582233837},{0.5933134892766008,0.5977928666675933,0.6079567995962282},{0.5972392814640548,0.585218595920636,0.61144499212512},{0.6106118988472149,0.600694306833566,0.6061511249762105},{0.6082180555800357,0.5950052277568356,0.5985888607953447},{0.6237982438102183,0.6089109044328584,0.5995068882469161},{0.5814118995347949,0.5941960752213256,0.5991507902337854},{0.5915098613581782,0.6100021521348508,0.6121863550793619},{0.600068901885015,0.6001811199945322,0.5977765694740292},{0.6028086249733966,0.6005477389981102,0.5940201105059557},{0.5973703131216579,0.6005890796164501,0.5832054183689609},{0.5911332223009282,0.5982293432053798,0.6071097698081196},{0.6139690531640734,0.617854209839819,0.5869042468065985},{0.596037791394557,0.5977684218965931,0.6076160973896115},{0.6198176842599691,0.608489913068894,0.5855736026800685},{0.5802479438010254,0.5914075733951445,0.5827950860824971},{0.5798218939093918,0.5979993685504977,0.5813470460076066},{0.5897126817461498,0.5892489137796184,0.604577220047457},{0.601128721221291,0.6063445434203858,0.5906390580701314},{0.5901586532197434,0.6075367374054111,0.5931204168743012},{0.5916274524621243,0.5964144265313889,0.607849909334079},{0.6000941686988243,0.588387585480878,0.6125925933294828},{0.5898386284602793,0.5814239081917385,0.6223777313617085},{0.596287198478031,0.5972383886056103,0.5890290826318072},{0.607627079446735,0.5981332572818732,0.5906192852269392},{0.5988933010972147,0.5907121252950921,0.6040932421227303},{0.5855637040387368,0.5861835569106545,0.6049842212958388},{0.6074554311354049,0.6083215468858262,0.5819505201735294},{0.5951268143305312,0.6201311342985714,0.5934807848051579},{0.6039406777111359,0.6022658102922847,0.6054807529710551},{0.6039703811942764,0.6036732189170728,0.597675542701594},{0.6119275530002459,0.5969766988315366,0.6043786340361785},{0.5984044018693669,0.5821819275691359,0.6060444804463573},{0.5895757207144292,0.6001301638415144,0.6020068766559522},{0.6011397305228123,0.6079878501304159,0.6064747931522313},{0.5884164839974497,0.6024634243919665,0.5952247404775959},{0.6174801785697102,0.5969106091197002,0.603694499960808},{0.6044704316653011,0.5991858468732164,0.5895392683589243},{0.609357142041598,0.6024006006839878,0.5866736959202942},{0.5945878434349167,0.5929114996492515,0.5809300782801482},{0.6260223696381205,0.5863269539855605,0.6104723089850804},{0.6084125652151526,0.602123666387177,0.6023050070795819},{0.5987701509529043,0.5990572149421053,0.5928700817300557},{0.588232247711843,0.6027656451405385,0.5971216238348679},{0.5924272950230807,0.6066597610725988,0.5780421821442421},{0.6083321867886661,0.5982364430385742,0.5987875066656457},{0.5876276381300659,0.6050635069749378,0.6111220126623835},{0.6007159682861534,0.6059030574550842,0.5985922577941405},{0.6015861172634533,0.6005400466690513,0.6029663246068007},{0.6126668019351182,0.6087122615181166,0.5938818299008445},{0.6071063966618814,0.6035443439632245,0.5943390534592322},{0.6028976597961303,0.599899984297845,0.5999361889411594},{0.5873339824810413,0.615846357117824,0.6218228706947074},{0.5994998071227466,0.5925556124383339,0.5734189597182678},{0.6022886336648311,0.6071126413537249,0.5985207369107478},{0.596327418355893,0.6056700311872694,0.5915121291417728},{0.6003693751303587,0.6002353323533052,0.5975496044975436},{0.5922705710271929,0.611935055777061,0.6062094087766258},{0.6071098385394563,0.5870075371429903,0.6059119206802972},{0.5988281050869342,0.6030662756197013,0.5799194028124502},{0.6105491413402466,0.6021188472055269,0.593086618658937},{0.6014444247575305,0.5937420169474874,0.614841835419263},{0.61032101238841,0.5984926248210346,0.5998578728252788},{0.5913981232720371,0.5969571872675374,0.5941230425067971},{0.5880018500985953,0.602104216729491,0.6008286715374779},{0.5974673182637923,0.5984142738528363,0.5904074860281785},{0.5891882201385903,0.5995719660907669,0.6009704710507195},{0.5920576114598509,0.6063518592663116,0.5987440909334516},{0.5774008839370056,0.596851350047889,0.5833796642763552},{0.6089028686211765,0.6034238246619378,0.5948005544682294},{0.6096313149646807,0.5985561376836938,0.5980893765439903},{0.6060784743648294,0.5842523993111295,0.6006140376850937},{0.6112158674876375,0.6145699291917824,0.6073939436221175},{0.5999186848448833,0.5927292314280386,0.6032069482626738},{0.6152276449196019,0.6009895114686499,0.5923621487409092},{0.6085633214694094,0.5907099108441156,0.611007970868237},{0.6045986536833843,0.6081392513574054,0.6186612025092029},{0.5989832470828199,0.5954096504482165,0.5986513080189954},{0.6026866389592989,0.6053147182055088,0.6092581788111806},{0.5786812830561704,0.6053185643946212,0.6045359791324497},{0.612694780747157,0.6001928920396378,0.6050250511750633},{0.594059889287767,0.6017163310870489,0.6063354866377442},{0.601459416027282,0.5922697819367855,0.6115139106753885},{0.5947876924001856,0.5946762568458289,0.6081566945568669},{0.5874721440202553,0.5859729727974883,0.5886270049816563},{0.6054876319540838,0.606068478029864,0.5906987183651213},{0.6072358453164843,0.5944317938013466,0.5954725310892597},{0.5892064876707701,0.6066812883381406,0.5925667667723868},{0.588913773897191,0.5998886447453993,0.6023113313327577},{0.5977690147734396,0.595629591147501,0.6025157907960345},{0.5984957474351192,0.5806724040558003,0.5952742450826126},{0.5965391844297976,0.5901313902187019,0.6030493414899499},{0.6163612813825335,0.6209277939762724,0.5929550952695745},{0.6147442504673002,0.5895905352830138,0.6054719429964982},{0.5929205499778698,0.5868132200823635,0.5942962979768243},{0.5790952118361313,0.6086701079310733,0.6151243788763772},{0.5966937421542653,0.6054736118656487,0.6065517944305016},{0.6025099380016022,0.5973525118053381,0.6128087160282156},{0.6038446446876014,0.6088358529252555,0.5914196863768748},{0.6041497329309796,0.5834122341358245,0.5964689080327488},{0.6069379807852224,0.5894941713899097,0.5971776427664096},{0.5988181715830847,0.6038218326729834,0.6191310594539968},{0.6047163653880437,0.5834633970968321,0.5747066348595775},{0.58466628859257,0.583374714712132,0.6103073429536506},{0.5904927628663348,0.5974210403777376,0.6072529732919331},{0.5958056460387317,0.606866995381085,0.6151194827138352},{0.6097193941074849,0.596119197908887,0.6091738299285234},{0.5904498179593773,0.5776619714902916,0.5802992945026434},{0.605622939074741,0.6093530995276312,0.6183186739376944},{0.5842110542427396,0.5896788943455298,0.6013905423926404},{0.6053962590513495,0.5988463680291123,0.5941471815840718},{0.6144461215606464,0.6017670533965118,0.5893522338375348},{0.5936059501765852,0.5988268671161731,0.5899270099742456},{0.6046673141033727,0.5979547617701837,0.5956939019362648},{0.5990463071819923,0.5952676473718904,0.6092508748703981},{0.618386839670763,0.5928673963043577,0.605109898617839},{0.6026973511979085,0.6145397132673883,0.5975022623057077},{0.6074399785742643,0.5901458632557159,0.5858748312494194},{0.5915902026631616,0.6032196720376107,0.6059840131672121},{0.6013946106771771,0.5942384637760563,0.5971923322227443},{0.5978946014596448,0.5956295268597513,0.5863412480805112},{0.5959229730258107,0.6223017183403601,0.6034272204851169},{0.6057915456804556,0.5908459837660173,0.5888439406735293},{0.6057080020604707,0.5953867137784279,0.5838253265370614},{0.5965305455956195,0.6112644184427894,0.5995621647740697},{0.5888165479576035,0.6076295995963393,0.5958362437594965},{0.5979014761184934,0.5885397726221575,0.6104607317553893},{0.5911110689313859,0.6027642549013652,0.5947282964049214},{0.5880119289783359,0.5885145493995946,0.5828784450071158},{0.6084330705064381,0.614963678829247,0.6095679542179041},{0.6004800469813439,0.6135664423550913,0.6035318124394735},{0.5998004100412541,0.6000766786844186,0.6042357652988296},{0.5855838774559228,0.5982382663496307,0.5868504284784543},{0.5969931274704235,0.597037264282875,0.6167853601419951},{0.5874585096659432,0.6068087537895129,0.5939917903563664},{0.5992020612863203,0.581820536032748,0.5915651933689424},{0.6128507467775535,0.5996426870166526,0.5846429866348987},{0.5927007000172855,0.6027399913746911,0.5963903278714776},{0.6175065856029358,0.590472148244959,0.6137759169361435},{0.6089939006872942,0.6161859712257075,0.5986343573612545},{0.6002541690061292,0.6170842527853306,0.5957759970137465},{0.5890740523197828,0.6064987262805633,0.5931513631367058},{0.609241584286301,0.611152725027502,0.588249844166829},{0.6130866247130295,0.5999410645823049,0.6083107062597075},{0.5969368540393823,0.6116981144098184,0.6065449590733217},{0.6129794271469681,0.5990631146599157,0.6056252917781061},{0.6124731594276501,0.6049317854419229,0.5957242344033582},{0.6292378479590638,0.603320559192687,0.6026696703278234},{0.6014552287994924,0.6179923736114756,0.6134450513761441},{0.6001626260710775,0.5946859448745312,0.6194431488982016},{0.6088490934268084,0.6101586664340656,0.5989578834056873},{0.6031113717121334,0.5976688606263871,0.6109995171036069},{0.6073774290863019,0.6065854902108326,0.5927065812723858},{0.5777796457933007,0.587476654576978,0.601979577684986},{0.5970505773229137,0.6116039577380094,0.5997473715850351},{0.6266805230239605,0.6023992309390391,0.626030428531738},{0.6073778992264747,0.6056724566226062,0.5946836433656192},{0.5993014119857343,0.6098862009559359,0.5994863630497134},{0.5953156810814184,0.6070194899385071,0.6132989326108269},{0.6093885118878271,0.5818040464616542,0.5814516459375648},{0.6000476649727505,0.6011827539549923,0.5990749997220339},{0.6132887428946192,0.5917428684333663,0.6167504589740379},{0.593637670261274,0.6019596438651207,0.6044288100506577},{0.5980745316083406,0.5987870739539509,0.5997396968544415},{0.6078972859453529,0.6118023818676251,0.5952443769302378},{0.6024490710772815,0.6106503453391876,0.5960865206095401},{0.5937571148699721,0.586639322303352,0.5924141324217029},{0.607181197123297,0.6167665891074084,0.5915354308892351},{0.597857779934598,0.593183606982072,0.5881251439407723},{0.6025097568679953,0.6094036076087328,0.6126525495520224},{0.6006141244247344,0.6045070795984923,0.6099445726151274},{0.6109435715968271,0.599914160156449,0.6096449711718689},{0.6141228996580335,0.5936003810705104,0.6091434847411581},{0.6190700349838933,0.6057628632098219,0.590055137648354},{0.598140742921001,0.5870472823269438,0.5997469693223848},{0.6081289234269335,0.5976385643198467,0.5959195964265854},{0.5984347911910064,0.5863671856850757,0.6073888550200784},{0.5978697341355511,0.5722505166959712,0.5984835657994171},{0.595376404705969,0.6164921876714641,0.5961045247160656},{0.6103820325528393,0.6110975845811218,0.6108270945797681},{0.5910730631090264,0.5965182155646015,0.6198891090716018},{0.5983653974201947,0.6092077233992857,0.6006857029188742},{0.6180475440119084,0.6028941445133975,0.5976654656350577},{0.6142543425214385,0.6151561376917082,0.5881007750107121},{0.5958828725990211,0.615637478019764,0.6101533788426087},{0.5850608212278668,0.6099323962560257,0.5874641715110952},{0.6107069853061381,0.6106021839235684,0.5943081570547859},{0.6037841566936235,0.6014698779969875,0.6202982600270014},{0.5973950102812879,0.5961077917388375,0.6043657069792786},{0.5897930093474016,0.5954069668237623,0.606208926527945},{0.5955268019188306,0.5859380712177547,0.6083058886165227},{0.5922996174195639,0.6189640215344168,0.6061420464806633},{0.6068308178645215,0.6113258154647807,0.6093450768530448},{0.5892305494602417,0.5957616967848864,0.5945186107962755},{0.6056198025055075,0.5931357512107236,0.5941148911719271},{0.5955493512588911,0.5914555848667334,0.6027908243323963},{0.6226670393870567,0.6052958747191404,0.6041782955780409},{0.588549812306494,0.6047856724781762,0.5995392183290623},{0.6043618379273448,0.5963832926115946,0.5946407168177196},{0.6001485484813474,0.5932803356122944,0.5865522257134081},{0.6036493065344187,0.6021521176727597,0.6127281012738853},{0.5942783789007993,0.6068410860044168,0.5913663074104405},{0.6133518904970771,0.5937533376013477,0.5839452462249858},{0.6049365023971651,0.5935435936276955,0.5940056803425048},{0.6109537918040456,0.5889424293603331,0.5974922497478828},{0.5831107895658716,0.6092192426568569,0.6001441435354938},{0.6006440452654455,0.6073463636568797,0.608133850584393},{0.6071518553787587,0.6021840752260218,0.603942626933083},{0.6001369473678151,0.6022167313782273,0.5873696826870529},{0.5984314388912115,0.5912636482636352,0.6082281726882877},{0.5883524092734751,0.5988765787426301,0.604022198860507},{0.584349043068201,0.5982542284645589,0.5876111216427993},{0.5943353748090761,0.5988857489501254,0.6145211830552649},{0.5854049551292035,0.602067599963242,0.6239062688741385},{0.6122568125484897,0.5943432401779065,0.5923378862375824},{0.6019813807101744,0.5908936212148436,0.6059124868593904},{0.6013212083901704,0.6137157200530758,0.5942764675632517},{0.6041467023884469,0.5874436969144798,0.6079134746351967},{0.6005897155224901,0.6045468320367071,0.5880441141777518},{0.5942186768765848,0.6180639913172369,0.5911006074044364},{0.6074622904737604,0.5969852241748487,0.6041916617734406},{0.5847028620457472,0.5886904696258757,0.6055151022120264},{0.615308313201326,0.596065612103531,0.6133847369253957},{0.6057296384918802,0.5890399917534773,0.594702678072456},{0.6160710430748741,0.6054460892530747,0.6031249188870165},{0.6185278955511987,0.6095468871291526,0.6071401787376618},{0.6173757986999017,0.5988625361230207,0.6214524014212465},{0.6111523895659731,0.6008059139400809,0.6010910796503214},{0.5981788954704905,0.6026537844877226,0.5898515750759932},{0.6003191838282687,0.5897422344213419,0.5984996066958527},{0.5870170569700135,0.6025063044823986,0.6089272902434268},{0.6121975332318421,0.5924066446228622,0.5940108330054459},{0.5896398813639003,0.6025728182072272,0.5996761343574752},{0.5901091492334055,0.6182959094394376,0.6094750009233857},{0.5965825282577276,0.6165232713412857,0.588363097823541},{0.608292469917752,0.6228463402080487,0.6008781829816097},{0.6181338068231088,0.6011544054617037,0.6066930050842306},{0.6094147292578302,0.6024922646850468,0.6047676256811075},{0.5985292845011891,0.5845765895422673,0.6002342919070196},{0.6282516121622895,0.5930722749499153,0.6016546752368572},{0.6014774540365018,0.5985660079576999,0.6005881406357709},{0.613229562604599,0.6121567084212753,0.5850301227275746},{0.6271305405042804,0.6080059159202967,0.5869778368931391},{0.6073844225607282,0.6014648991154736,0.594040800145278},{0.6087067250309051,0.6003081107765945,0.5876002220983121},{0.6085958099575504,0.5946456026140066,0.6149644481124437},{0.600648790254993,0.5966787856057602,0.6128722277111187},{0.5926900309468262,0.6037756372781939,0.5924895800279432},{0.5955937339851577,0.6078407032517321,0.6006879004098721},{0.6096917047308352,0.6029051176908264,0.6026781622113074},{0.6291507856714446,0.5978943723407107,0.5911762675171579},{0.6094198802897473,0.6200252031735664,0.6172199045537152},{0.6125535718248499,0.6198917610209187,0.6043299727516722}};
                char* data_str = serialize(kirat_data, n);
                printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            }

            // // Generate shared secret and encrypt it with SK, if attestation passed.
            uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = {0};
            p_att_result_msg->secret.payload_size = SIZE_OF_MESSAGE;
            if((IAS_QUOTE_OK == attestation_report.status) &&
            (IAS_PSE_OK == attestation_report.pse_status) &&
            (isv_policy_passed == true))
            {
                ret = sample_rijndael128GCM_encrypt(&g_sp_db.sk_key,
                            &g_secret[0],
                            p_att_result_msg->secret.payload_size,
                            p_att_result_msg->secret.payload,
                            &aes_gcm_iv[0],
                            SAMPLE_SP_IV_SIZE,
                            NULL,
                            0,
                            &p_att_result_msg->secret.payload_tag);
            }

        } else if (message_from_machine_to_enclave == RETRIEVE_CAPABLITY_KEY_CONSTANT) { 

            // //Retrieve the capability key
            // char* split = strtok(optional_message, ":");
            // printf("Message is %s\n", optional_message);
            // char* currentMachineID = split;
            // split = strtok(NULL, ":");
            // char* childID = split;

            // char* capabilityKey = retrieveCapabilityKey(currentMachineID, childID);


            // strcpy((char*)g_secret, capabilityKey);


            // // Generate shared secret and encrypt it with SK, if attestation passed.
            // uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = {0};
            // p_att_result_msg->secret.payload_size = SIZE_OF_MESSAGE;
            // if((IAS_QUOTE_OK == attestation_report.status) &&
            // (IAS_PSE_OK == attestation_report.pse_status) &&
            // (isv_policy_passed == true))
            // {
            //     ret = sample_rijndael128GCM_encrypt(&g_sp_db.sk_key,
            //                 &g_secret[0],
            //                 p_att_result_msg->secret.payload_size,
            //                 p_att_result_msg->secret.payload,
            //                 &aes_gcm_iv[0],
            //                 SAMPLE_SP_IV_SIZE,
            //                 NULL,
            //                 0,
            //                 &p_att_result_msg->secret.payload_tag);
            // }

        } else {
        //     //TODO investigage why if we don't have this else case, the old message is leaked
        //     //and given to the requesting party. Ex -> comment out this else case, and 
        //     //in retrieveCapabilityKey in enclave.cpp, call with message_from_machien_to_encalve = 3
        //     char* capabilityKey = "INVALID REQUEST";


        //     strcpy((char*)g_secret, capabilityKey);


        //     // Generate shared secret and encrypt it with SK, if attestation passed.
        //     uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = {0};
        //     p_att_result_msg->secret.payload_size = SIZE_OF_MESSAGE;
        //     if((IAS_QUOTE_OK == attestation_report.status) &&
        //     (IAS_PSE_OK == attestation_report.pse_status) &&
        //     (isv_policy_passed == true))
        //     {
        //         ret = sample_rijndael128GCM_encrypt(&g_sp_db.sk_key,
        //                     &g_secret[0],
        //                     p_att_result_msg->secret.payload_size,
        //                     p_att_result_msg->secret.payload,
        //                     &aes_gcm_iv[0],
        //                     SAMPLE_SP_IV_SIZE,
        //                     NULL,
        //                     0,
        //                     &p_att_result_msg->secret.payload_tag);
        //     }

        }

        
    }while(0);

    if(ret)
    {
        *pp_att_result_msg = NULL;
        SAFE_FREE(p_att_result_msg_full);
    }
    else
    {
        // Freed by the network simulator in ra_free_network_response_buffer
        *pp_att_result_msg = p_att_result_msg_full;
    }
    return ret;
}

//When Ping machine receives an encrypted secret from the Pong enclave
//We have already created an attestation channel before this point
inline int ocall_ping_machine_receive_encrypted_message(uint8_t *p_secret,  
                                uint32_t secret_size,
                                 uint8_t *p_gcm_mac) {

        uint8_t aes_gcm_iv[12] = {0};
        int ret = 0;
        sample_rijndael128GCM_encrypt(&g_sp_db.sk_key, //used to decrypt in this case
                            p_secret,
                            secret_size,
                            &g_secret[0],
                            &aes_gcm_iv[0],
                            SAMPLE_SP_IV_SIZE,
                            NULL,
                            0,
                            (sample_aes_gcm_128bit_tag_t *)p_gcm_mac);
        //printf("Secret is %s\n" , (char*)g_secret);

        uint32_t i;
        bool secret_match = true;
        // handle_incoming_events_ping_machine(atoi((char*) g_secret));
        return 0;
}

void bank2_start_fn() {
    enclave_start_attestation("KPS2", 1);
}


inline int createCapabilityKey(char* newMachinePublicIDKey, char* parentTrustedMachinePublicIDKey) {
    //TODO Make this generate a random key
    sprintf(secure_message, "%s", "CAPTAINKEY");
    capabilityKeyDictionary[string(newMachinePublicIDKey)] = string(secure_message);
    //printf("The capability key stored on KPS as: %s\n", capabilityKeyDictionary[string(newMachineID)].c_str() );

    capabilityKeyAccessDictionary[string(newMachinePublicIDKey)] = string(parentTrustedMachinePublicIDKey);
    //printf("New machine ID: %s\n", newMachineID);

}

inline char* retrieveCapabilityKey(char* currentMachinePublicIDKey, char* childMachinePublicIDKey) {
    //printf("Current machine ID: %s\n", currentMachineID);
    //printf("Child machine ID: %s\n", childMachinePublicIDKey);

    if (capabilityKeyAccessDictionary[string(childMachinePublicIDKey)].compare(string(currentMachinePublicIDKey)) == 0) {
        //printf("The capability key is : %s", capabilityKeyDictionary[string(childMachinePublicIDKey)].c_str());
        char* returnCapabilityKey = (char*) malloc(SIZE_OF_CAPABILITYKEY);
        memcpy(returnCapabilityKey, capabilityKeyDictionary[string(childMachinePublicIDKey)].c_str(), SIZE_OF_CAPABILITYKEY);
        return (char*) returnCapabilityKey;
    } else {
        return "Access Prohibited!";
    }
    

}