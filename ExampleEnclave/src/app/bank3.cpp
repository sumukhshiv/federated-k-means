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
#include "bank3.h"
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
int bank3_sp_ra_proc_msg0_req(const sample_ra_msg0_t *p_msg0,
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
int bank3_sp_ra_proc_msg1_req(const sample_ra_msg1_t *p_msg1,
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
int bank3_sp_ra_proc_msg3_req(const sample_ra_msg3_t *p_msg3,
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
            // double kirat_data[40][3] = {{0.6077049930996429,0.6077049930996429,0.6077049930996429},{0.5911618817816682,0.5911618817816682,0.5911618817816682},{0.5982867199332335,0.5982867199332335,0.5982867199332335},{0.605950938928775,0.605950938928775,0.605950938928775},{0.6165454308890274,0.6165454308890274,0.6165454308890274},{0.5937022166689185,0.5937022166689185,0.5937022166689185},{0.5990321836737337,0.5990321836737337,0.5990321836737337},{0.5871030592614939,0.5871030592614939,0.5871030592614939},{0.5930022282063667,0.5930022282063667,0.5930022282063667},{0.6130757252683101,0.6130757252683101,0.6130757252683101},{0.5978220475471928,0.5978220475471928,0.5978220475471928},{0.5872872348637117,0.5872872348637117,0.5872872348637117},{0.5880892314515322,0.5880892314515322,0.5880892314515322},{0.6070730159438522,0.6070730159438522,0.6070730159438522},{0.5894143782658511,0.5894143782658511,0.5894143782658511},{0.599005391327391,0.599005391327391,0.599005391327391},{0.6036133597799735,0.6036133597799735,0.6036133597799735},{0.6072065062391973,0.6072065062391973,0.6072065062391973},{0.5996041984673666,0.5996041984673666,0.5996041984673666},{0.6118012000166696,0.6118012000166696,0.6118012000166696},{0.5939191739484727,0.5939191739484727,0.5939191739484727},{0.5886750065063125,0.5886750065063125,0.5886750065063125},{0.5997426684771702,0.5997426684771702,0.5997426684771702},{0.6102334863401919,0.6102334863401919,0.6102334863401919},{0.5912972333278679,0.5912972333278679,0.5912972333278679},{0.6025604243740265,0.6025604243740265,0.6025604243740265},{0.6219972918131564,0.6219972918131564,0.6219972918131564},{0.5923896403159432,0.5923896403159432,0.5923896403159432},{0.6027579545288441,0.6027579545288441,0.6027579545288441},{0.5919086122601278,0.5919086122601278,0.5919086122601278},{0.5893599381995716,0.5893599381995716,0.5893599381995716},{0.5810214653023501,0.5810214653023501,0.5810214653023501},{0.589016806862104,0.589016806862104,0.589016806862104},{0.5911380139516503,0.5911380139516503,0.5911380139516503},{0.5970084355685829,0.5970084355685829,0.5970084355685829},{0.5993451823616759,0.5993451823616759,0.5993451823616759},{0.6033988664617769,0.6033988664617769,0.6033988664617769},{0.6096485616936191,0.6096485616936191,0.6096485616936191},{0.6025352417947997,0.6025352417947997,0.6025352417947997},{0.5897520322856289,0.5897520322856289,0.5897520322856289}};
            
            if (TEST_CONSTANT == 0) {
                double kirat_data[30][3] = {{0.5978220475471928,0.5978220475471928,0.5978220475471928},{0.5872872348637117,0.5872872348637117,0.5872872348637117},{0.5880892314515322,0.5880892314515322,0.5880892314515322},{0.6070730159438522,0.6070730159438522,0.6070730159438522},{0.5894143782658511,0.5894143782658511,0.5894143782658511},{0.599005391327391,0.599005391327391,0.599005391327391},{0.6036133597799735,0.6036133597799735,0.6036133597799735},{0.6072065062391973,0.6072065062391973,0.6072065062391973},{0.5996041984673666,0.5996041984673666,0.5996041984673666},{0.6118012000166696,0.6118012000166696,0.6118012000166696},{0.5939191739484727,0.5939191739484727,0.5939191739484727},{0.5886750065063125,0.5886750065063125,0.5886750065063125},{0.5997426684771702,0.5997426684771702,0.5997426684771702},{0.6102334863401919,0.6102334863401919,0.6102334863401919},{0.5912972333278679,0.5912972333278679,0.5912972333278679},{0.6025604243740265,0.6025604243740265,0.6025604243740265},{0.6219972918131564,0.6219972918131564,0.6219972918131564},{0.5923896403159432,0.5923896403159432,0.5923896403159432},{0.6027579545288441,0.6027579545288441,0.6027579545288441},{0.5919086122601278,0.5919086122601278,0.5919086122601278},{0.5893599381995716,0.5893599381995716,0.5893599381995716},{0.5810214653023501,0.5810214653023501,0.5810214653023501},{0.589016806862104,0.589016806862104,0.589016806862104},{0.5911380139516503,0.5911380139516503,0.5911380139516503},{0.5970084355685829,0.5970084355685829,0.5970084355685829},{0.5993451823616759,0.5993451823616759,0.5993451823616759},{0.6033988664617769,0.6033988664617769,0.6033988664617769},{0.6096485616936191,0.6096485616936191,0.6096485616936191},{0.6025352417947997,0.6025352417947997,0.6025352417947997},{0.5897520322856289,0.5897520322856289,0.5897520322856289}};
                char* data_str = serialize(kirat_data, 30);
                printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 1) {
                double kirat_data[60][3] = {{0.8911517818119197,0.9020596991405672,0.9066793462854885},{0.8911569118573369,0.8916579474307605,0.8917570339412065},{0.8837866877629412,0.9034183588063983,0.8864289516978063},{0.8979787550242192,0.8997623324676169,0.8805130788904092},{0.9054852336407244,0.9129251632506696,0.9095104277323772},{0.8983598392777862,0.9054854081881577,0.9118606949714539},{0.9082394572775815,0.8884739131824317,0.8966627985892267},{0.8839365557179699,0.8845701751257453,0.9074173591697202},{0.9013628861700183,0.8899505454083128,0.9057597213874282},{0.903710243637147,0.9052452168888381,0.9004559873642632},{0.9046307878291314,0.8938183061273482,0.9176481106330532},{0.8840179845329511,0.8922448594533834,0.9129140283539409},{0.8868439302969396,0.9021665060523604,0.897647719482885},{0.9063197916885652,0.8880604343402094,0.8736188462798569},{0.8908061185784234,0.8945561848400687,0.9049097817201498},{0.9150069400159867,0.8949932526426424,0.9027491783441433},{0.8995520538856233,0.9055310553135668,0.8903775778522974},{0.898940549588701,0.8859408588896219,0.9073001740168135},{0.9136200171518697,0.8916098361047697,0.9119818500007534},{0.9033278599427037,0.8907301955946368,0.9024313231524178},{0.9001969100458207,0.9140981675626481,0.906583732299702},{0.9093222694718939,0.9034567573636485,0.9130969722655781},{0.8966024539022937,0.8990998817294855,0.9068331858808729},{0.9017137389288297,0.9133188640379888,0.9073547698378546},{0.8962616168179088,0.8979319512630701,0.9011575420998846},{0.8840331859666397,0.928526130579768,0.9172352217339701},{0.9079439702454035,0.9071871025883187,0.9096706518446106},{0.9086423969659447,0.8945207247407434,0.9072303025207796},{0.8901750827876571,0.8897043099311625,0.9238918949921169},{0.8987339227411348,0.9025502887993218,0.8960868931262609},{0.9045985545112363,0.9121041240622174,0.9003414800598278},{0.9141071259098948,0.8944200947849024,0.9038653224237252},{0.9237725391815381,0.8830745996535863,0.889343599407084},{0.9017595336362522,0.9019141383129352,0.8947334225590138},{0.8965399761828612,0.8880551510048617,0.8931471841144835},{0.8933706654908478,0.8894849874705458,0.9273679996090957},{0.8940062769869843,0.9010756362202812,0.9002809896079884},{0.8864092820511559,0.8993494287698319,0.9093818086700786},{0.8938813732297977,0.8820952797115752,0.9020726199904959},{0.8906448664745575,0.8943739859840887,0.90299109705748},{0.9080805448238712,0.9071777416250479,0.8909206643761362},{0.9006365017844139,0.9070973034876616,0.9060910206517846},{0.910780783739046,0.9092402487909347,0.8882569650569735},{0.8972447301631121,0.8974887719485679,0.9000288059780323},{0.8971141704531338,0.8917366616061883,0.9050361579459979},{0.9085525157839865,0.877342682464091,0.8969202935672975},{0.8945670082960168,0.9044209976026956,0.9047218749353142},{0.9154222817636561,0.9009422409676658,0.8828001295134925},{0.9047958633955053,0.9149354870987676,0.8992185613499915},{0.9061008293512155,0.9142071877255465,0.8924296640909097},{0.8996039690982186,0.9049404536456992,0.8866018789395035},{0.9083596752028967,0.8938178733685304,0.9135138361081846},{0.8943349773219635,0.9107503718320984,0.8896011998684431},{0.9108585484766489,0.9086542258983548,0.9074771416367499},{0.881411073556976,0.9013341048674886,0.8990643484915501},{0.8873621424054362,0.9153759762992418,0.8929976949368804},{0.9079189292390464,0.8993019079370198,0.89820432884885},{0.9005174159120168,0.9065758403426074,0.9074644236194844},{0.8970638231601584,0.8860632908022091,0.8907140716782415},{0.8916986244525588,0.9204327342677205,0.8906302080529306}};
                char* data_str = serialize(kirat_data, 60);
                printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 2) {
                double kirat_data[120][3] = {{0.8967733069291857,0.9115398966902019,0.9085275516955374},{0.9203620378638512,0.9097168962598842,0.9109256226114013},{0.8782511456640857,0.8913011802717806,0.9056680220444127},{0.9043037369424908,0.9010963058235798,0.8978881237577571},{0.9033620416152156,0.9156642388712883,0.8866653872960764},{0.8979726775453998,0.906561997508267,0.9044044235863694},{0.8921008664824299,0.8870666874837903,0.9053335831301804},{0.9017541335222026,0.9008580018698435,0.8987863527378622},{0.877129566351467,0.9015589998424801,0.9079524074370984},{0.8948475603215146,0.9085828889723676,0.9144356788424313},{0.9031648231417817,0.8881191122968211,0.8899260070976609},{0.888237087162026,0.9084623499698276,0.890517585722273},{0.895103053103745,0.9004111173055633,0.9070782557373145},{0.9025258620982315,0.9117448020974427,0.8997989899043749},{0.9062106626500444,0.8957004755493052,0.8991487426287391},{0.8954152193647023,0.9052304053106618,0.9087698617515346},{0.8919982954193456,0.8930128700291067,0.8878368083612184},{0.9076940237070203,0.8771263941080716,0.898752238497792},{0.9005636244968556,0.9230994816936136,0.8995874969818067},{0.9001966295696636,0.8962341393348371,0.8946326043211317},{0.9090254192111527,0.8952366251549176,0.9043325871971887},{0.9162583794071018,0.8851321038995519,0.9090674843879213},{0.8975482327127389,0.8909648762536916,0.9111816962926695},{0.8931613834436999,0.9023612910198978,0.9023609013788942},{0.8958374062370767,0.9164574174962491,0.8898282315613242},{0.9053693450591567,0.8981971644457695,0.8909157934599758},{0.8828198465498116,0.8872270622893932,0.8891434052321261},{0.9010773330908303,0.9016653922981497,0.8902428203292378},{0.8958861851140723,0.9010343034960338,0.8728697934455263},{0.8957837097479227,0.9025571109963365,0.9030769615570945},{0.9020671711677085,0.9038454537286598,0.9056661738678843},{0.8914468965174331,0.8902181475584358,0.9067296610328065},{0.9193351328769912,0.9037964883257081,0.9149366761604798},{0.9008483990184506,0.9087605300021343,0.9008686609530642},{0.9046302563479506,0.911587600410827,0.9112611980390395},{0.8939406700470044,0.916268907002515,0.8919746879543713},{0.9169563147666976,0.8923852178277425,0.9130885491598076},{0.9040839804271803,0.9140390951134532,0.8933054120380735},{0.905950741841932,0.9139369477643431,0.8928114123745051},{0.9188054841988113,0.8992196389860827,0.9008885399308197},{0.8848525583166532,0.9143810944301829,0.8983549537757904},{0.9000498774869575,0.9015718757563926,0.8939145571147605},{0.9036030699531734,0.8967005845552348,0.9104416662914447},{0.8956105237685602,0.8941224482330041,0.9043840966667835},{0.8982524955398281,0.9016622443788387,0.905548646748911},{0.8876344556643093,0.8889959253234742,0.9007094493203073},{0.8946217306577922,0.9071716934317077,0.9062167506646112},{0.9005010590175944,0.8932269488208198,0.9119657442728034},{0.9063123696127545,0.8911124964991387,0.891043234595421},{0.9033170813899534,0.8878264059340387,0.9110137910833729},{0.8937460720909841,0.8951287732467957,0.9085335103950799},{0.9047250439742678,0.9149758380418666,0.9153233257455902},{0.9103832577936061,0.8896731215571774,0.8926543845608512},{0.9021025615660504,0.8902090581162589,0.9072385841126857},{0.8890648869512117,0.9013017251348391,0.9033940275704432},{0.8930893410754257,0.9055251209433303,0.9275596016576146},{0.9046582571853662,0.9060321006936065,0.9037157669254139},{0.9062043913015808,0.8887424624023688,0.8969293114065865},{0.9009933681024397,0.9230232062779345,0.8919838049631691},{0.913945415834384,0.8953222743845324,0.8825705396505494},{0.8890084787646566,0.9132646518995508,0.9079784824529026},{0.9016993421377385,0.8925118206695748,0.8848581595142335},{0.8874950657706203,0.9083255105043407,0.91528422802079},{0.9116576364299264,0.8972509245632442,0.8934241570439982},{0.8947480989612543,0.8927675117146524,0.897519762625331},{0.9004247351521346,0.8870552073486992,0.8974471292509028},{0.8911441483217698,0.8963953549902509,0.8915979280627195},{0.9288878704411896,0.8875533653233718,0.9026212083565538},{0.8969703074298202,0.9184390905865365,0.9194321294858765},{0.9074348284123539,0.8828945885047258,0.9170358131130972},{0.8875447524883149,0.9004770631675518,0.8907442948815234},{0.8871353224671146,0.9034813326548823,0.8987826690953742},{0.8977473721007964,0.9059890826100225,0.8974948588112821},{0.8943249302319635,0.90328783391961,0.8937204198622513},{0.9072156364071216,0.894401142444404,0.8948722544557075},{0.8990419714215404,0.9041281828942641,0.9033505631390584},{0.8961876340167301,0.8967785173686773,0.9032133454327557},{0.9014208203261963,0.9039714790938334,0.9068921337419815},{0.8978714575247461,0.9047639492060847,0.9050792565245342},{0.8976278704202784,0.8969069803617131,0.8942134048617382},{0.9072211604343154,0.8984961882076132,0.8862759046255362},{0.8841346918635908,0.9037573706895604,0.884963644332575},{0.9090322734618774,0.9052185839082677,0.9087116765905975},{0.8921581090228191,0.9085555836968058,0.8885306311446812},{0.8977158961457635,0.8989186920489002,0.8911808165660655},{0.9114096218154076,0.9069457114072903,0.915929245544521},{0.9047125373234727,0.8769997854000243,0.9100880907138952},{0.9076389945546489,0.8903632576502987,0.8956107501478286},{0.8976606561708272,0.9079691770104569,0.9134164148947008},{0.8965068541473851,0.900156747684006,0.8846798063136881},{0.9185770780847761,0.9044900325201738,0.8892802990891749},{0.8994099017846193,0.8969441152753874,0.9043151370936987},{0.9075627776207998,0.9010849476102805,0.8994503905019398},{0.8864621485578407,0.9020009732359674,0.8958822944607703},{0.8948259354701052,0.9062052596748672,0.9015006883574683},{0.9075186848341392,0.8947349113063917,0.9009366094680623},{0.8848848493370632,0.8867937628974121,0.9027409823048071},{0.8925216574892948,0.8936530358414001,0.8911244871868778},{0.8892148592806808,0.9041016443234798,0.8757137536971067},{0.9107771216642556,0.8941591304079715,0.8999288409232783},{0.8951316896514208,0.8969855543924489,0.8936139825882333},{0.9013894836741508,0.8917003492359417,0.9003043699610007},{0.9019360602292265,0.9147248656946694,0.8946249559045127},{0.9013933468010272,0.8839786861187808,0.9067840418138049},{0.8830192628779562,0.8970490039957352,0.9277278371567025},{0.8984754948238246,0.8899689229177757,0.8900333408799871},{0.9021545782963757,0.8891900271279414,0.8840923364652373},{0.9163213345506388,0.899686505896611,0.8990460270031247},{0.8933826079491691,0.9226630656598894,0.908397406471765},{0.884132089605911,0.91888954873339,0.8939103728711483},{0.9047133209669328,0.9001755189875426,0.9007744579592966},{0.889133287765454,0.8909369430313703,0.9108359422604034},{0.9061427471133069,0.8983759070024739,0.8788906977486631},{0.9004289048808332,0.9004698182241953,0.8904944780860995},{0.9181648647816817,0.9008497155684714,0.9024179726674633},{0.8965505599789455,0.879416878504419,0.8973912906623952},{0.9010503775428328,0.8947694214886139,0.9045672781041996},{0.9092714429884269,0.8940412811313181,0.9090340866700016},{0.8986722454081484,0.8919319154692211,0.8935294765204201},{0.9089129675568656,0.9009239841008871,0.9041541799457175}};
                char* data_str = serialize(kirat_data, 120);
                printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 3) {
                double kirat_data[240][3] = {{0.9048189065026008,0.8796506649051004,0.8866084801838074},{0.9028657486632115,0.9130265571664947,0.9128950332050269},{0.9219756855870886,0.8813818103763998,0.887886649645847},{0.9102753726138623,0.9020060190272661,0.8901378841965253},{0.893823490174418,0.8947909805952969,0.9095090652502321},{0.9192254248197677,0.8884837767179761,0.9142555259346811},{0.8951102203907918,0.8922770988581983,0.9013882599380917},{0.9257029214081869,0.9117872993735517,0.9021498824185433},{0.9048060379385212,0.9002266962006247,0.916348304978882},{0.9147741776484631,0.8711592974996385,0.9085263437306437},{0.9064637015236727,0.9015019160438515,0.9070822564523879},{0.8963875153218268,0.9028558163262778,0.8928302898556837},{0.9149331515745539,0.8926327088650505,0.8963540272196063},{0.9011353686036784,0.8924759970418247,0.8853126260432759},{0.8976385021492986,0.8931355372721898,0.9000606934934552},{0.8850949253994299,0.9024818545757484,0.8894728688780061},{0.9019028538927291,0.8895747277841778,0.8900159886074006},{0.904643649202782,0.9067579739704474,0.9122792572622485},{0.9161868359925542,0.898513184950558,0.9121188015496818},{0.9024386544032736,0.89005174241003,0.9008878204100473},{0.9004656094986855,0.9218319948378982,0.9061247468721407},{0.9050234867188068,0.9035952172489089,0.896076399513185},{0.9019301534140236,0.9150454433646338,0.90160848353769},{0.8928717546243942,0.9056676985107461,0.9103767978612347},{0.9062539011162584,0.90156595023175,0.8822285321371276},{0.9033874924466755,0.8829582167036533,0.9102283700622322},{0.9028431767428773,0.9178197419681172,0.906211631410131},{0.8947400285228166,0.8945669718596574,0.9079772520176356},{0.888574009534983,0.8989851956478014,0.8946594845460614},{0.8796249452438119,0.9086828000700693,0.8863759220221119},{0.8995672504050942,0.8931098862987875,0.912324091404779},{0.9031342709502834,0.9090088128938023,0.9053633118907906},{0.9199551294584198,0.9043765742712231,0.8783191894051918},{0.8973699129197613,0.8901037843242908,0.9161514762090737},{0.8926951293206828,0.9067318575632738,0.8928045910868615},{0.9124692452073657,0.8942282960200612,0.9061515671166863},{0.9138941546302313,0.8957577227445799,0.9055576066582788},{0.9074147154590333,0.8983345374011,0.9127745228308671},{0.9101523444823675,0.8967095835351635,0.9190237247507955},{0.9110656539303758,0.8946135219977941,0.8898700115550363},{0.913987150072095,0.8952049537818806,0.8913099542834775},{0.9152842144730993,0.9122962746390257,0.9025013754383316},{0.8840048011721959,0.8926815155521566,0.8830054952124445},{0.9071126079580987,0.9176516783983507,0.9043549521517136},{0.9129556868010071,0.8826131420757078,0.9327402119421231},{0.8976467758490407,0.8962560006762885,0.8956489243619696},{0.9096968883485034,0.9022669176294154,0.883751167080204},{0.8987396502385515,0.9061762986429969,0.8963812276649638},{0.912524559365092,0.8959663428483357,0.9102543359543193},{0.9197846749926323,0.9048000816364575,0.9041763129162418},{0.9033697401881852,0.903682805804592,0.8916225393304655},{0.9095142992137005,0.8902332552547987,0.9039796904703415},{0.9016904959604184,0.9221081735586537,0.9188305839653876},{0.9149126328552271,0.8883480024272298,0.9006866438496755},{0.8916901794200782,0.9116657386234187,0.9092095966705015},{0.9033401007200393,0.9091102657922534,0.8978546410376479},{0.9015827288862474,0.9092617611567376,0.9147531378681613},{0.8688982926404324,0.9090561799095115,0.8957193151992032},{0.9021851713486642,0.8990806147249276,0.892076551392238},{0.8962012459965556,0.9022542111346001,0.8901669327375191},{0.876384745248393,0.9176449292903776,0.9115937746453644},{0.9012676885430346,0.9054588888116286,0.8857743571823109},{0.8919616485608132,0.8970776769504777,0.8916797577227716},{0.901120200675938,0.8900289982619332,0.8782707095294084},{0.9059475633157994,0.8894461924863608,0.9083614907503349},{0.907341057180951,0.898416053702429,0.915796855645299},{0.8955219558546782,0.9142285803261736,0.8920385260201497},{0.9103192806435533,0.8929237608508424,0.8954700180399194},{0.8827617225052954,0.9087425546457595,0.8967296230887087},{0.8934853301058339,0.8862568773930541,0.8996578221433453},{0.8837051625323993,0.8990900312401178,0.8917736151764191},{0.8779754725606773,0.8909210768484666,0.9073716982984035},{0.8952488235264706,0.8985503244293616,0.8929546050765387},{0.8982499533484216,0.8960837724588293,0.8952446670497856},{0.9083554409890455,0.8843697193981469,0.9110333459703335},{0.8874670245330655,0.8883370363767291,0.9037805140867871},{0.8964490394420389,0.9004857727459141,0.9152096065671771},{0.8882417622387285,0.9102503521094529,0.915925848682538},{0.9030122406349993,0.8936512835634787,0.8893653003217089},{0.8947968104871511,0.9169426771892063,0.9115704361132433},{0.9113798291844859,0.8990825058996191,0.9193762828488562},{0.901194326199429,0.9188293554142891,0.8884990986079122},{0.8910937397690623,0.9091036458798838,0.9217300113439505},{0.9111323894214228,0.9034199736479569,0.9021158442796298},{0.8928243928562237,0.8805342137133938,0.9102635030889187},{0.9055900170922828,0.8861327340956472,0.9007835471485995},{0.9108945281242439,0.8967050241609659,0.9024779120520494},{0.9279136601191712,0.903480276086269,0.895904417615494},{0.8858637624157183,0.912961774606226,0.901609499258444},{0.9060344244694194,0.9141244101703931,0.9159504367842072},{0.9140120291782695,0.8917481274866851,0.8915998202130363},{0.8853729726772679,0.8989575050203711,0.9128721408699118},{0.8989099207471365,0.8998258052629788,0.8997715883014887},{0.9178009087848494,0.9072660188102094,0.9080999035484344},{0.9017320730128273,0.9103911581756388,0.9073666889838404},{0.8932479639705048,0.8861308300836549,0.8807666919225583},{0.9053367138297679,0.901838935318657,0.8848835174123048},{0.900708162259967,0.8926687515434977,0.8883721090125936},{0.9154771990751507,0.8999074473953483,0.8998008359518361},{0.9123365998308889,0.9030104458322837,0.9064364335231245},{0.9005124924910429,0.8996412569260626,0.9012874958042847},{0.9155893844081041,0.8978619832672143,0.9075917398443181},{0.8961422010396806,0.9051915334660398,0.9163472307098273},{0.9095887776471534,0.9059024250462876,0.9012383425926551},{0.8996311476974782,0.897663930895043,0.8980185079501718},{0.8962829956419653,0.9027142035305851,0.9187950434914073},{0.8963795869875277,0.8990893573222485,0.8939364549644744},{0.9028484009426099,0.9017787691650815,0.8943899749166151},{0.8925087973827521,0.9068964891397663,0.9085624587086449},{0.8882393137188316,0.8980114816495429,0.912473510523159},{0.9064321854144503,0.9006896275715719,0.9062682232399516},{0.8950255721337196,0.9027012512365606,0.8855812711459199},{0.8907901576736514,0.8915867302036423,0.9095826532876925},{0.8874996061575471,0.9001016595653913,0.9023734402200825},{0.8866248255652865,0.8998159883820932,0.8804541331924864},{0.8894780042416702,0.9030637409164939,0.9179930624542617},{0.9050810874763316,0.9087283304322356,0.905369096703168},{0.8724106089591892,0.8798900343082094,0.9064989871466285},{0.9071833533234973,0.9005245910224393,0.889423932756336},{0.8902733024500251,0.9037539736605438,0.8947588919631854},{0.9027130769921671,0.9004373752653423,0.8929141126704097},{0.899908456442462,0.8940049430256037,0.9078832550800148},{0.9077688496354948,0.9074171721844273,0.8959685711139226},{0.8906967230874564,0.901514484985077,0.9240236765826534},{0.8907271526074462,0.8950707455482211,0.8949186934046105},{0.9168250580579539,0.9067954304270773,0.8861091968456364},{0.9152251706378217,0.8982891534098065,0.9109517892288794},{0.8981264174909745,0.9095138035049783,0.9137548475200521},{0.9186324527846693,0.8988534559808827,0.8916172152201274},{0.9018179559758281,0.8996234512574897,0.8927320173260882},{0.8864726898456848,0.9258499229359385,0.9096155953831266},{0.9077558948758033,0.9219905027435915,0.8991399831395973},{0.9055714621007946,0.9084868561387514,0.8969862078792903},{0.8880613044941139,0.9006523544654869,0.9206831032075309},{0.9012004704126354,0.9089702587876335,0.8988351701389514},{0.8867577558567388,0.8867544602708889,0.9183829298963945},{0.9025690387695573,0.8976332980574111,0.9051266089022147},{0.9107438263573601,0.8849070620662669,0.8834495195084583},{0.890987520804972,0.9213680846713698,0.896096769484414},{0.8979305608601055,0.8811472666918674,0.8889623888819893},{0.897407373654098,0.8930764424464013,0.8905863205917196},{0.9170295432242936,0.8938822519405252,0.8877838266718554},{0.8887020482082573,0.8897439312021775,0.9065963001768432},{0.8970207356847025,0.8995758837653249,0.8709322840004461},{0.8973690534146441,0.8985583862526684,0.9038758501095226},{0.8894406590218512,0.8952686946551629,0.8986158030721579},{0.8862347505991977,0.8844224881275882,0.9071307875686772},{0.9121186146658457,0.8962078024710158,0.9014935188373572},{0.8881886425781601,0.9128093113497153,0.9025642906601666},{0.9246074225592064,0.9038567893313229,0.9091783403827323},{0.9019706915145591,0.8852362160663745,0.9147670376993214},{0.8943101136817843,0.9051514292080005,0.9110088110069747},{0.9052986498170723,0.8989716117046985,0.9181771825196877},{0.9079842225821777,0.895317001911559,0.8902858615175654},{0.911691611293214,0.9163675513189852,0.9122884862152003},{0.8885284484847201,0.8992562625244724,0.8997185734262828},{0.9162495827552422,0.8960888496684186,0.8961118307318867},{0.8846582449220024,0.8975497261111182,0.8881672741376364},{0.9031619382343575,0.904970251511084,0.9157116815158122},{0.8979528005983791,0.8929729958033337,0.8909283210945009},{0.9112466923588991,0.887358053240927,0.9239912094755688},{0.9040875772121966,0.9088839491385624,0.8947579077257763},{0.9232855770278522,0.9264187756388004,0.8838870748463248},{0.9058245668682056,0.8919932826058876,0.8954830453208926},{0.8939168579030777,0.8849609966883454,0.9067548315256895},{0.9139845203665725,0.8936869652222201,0.9035912387973427},{0.9148696102282288,0.8922449667919499,0.8900389928225155},{0.8964543963653846,0.9027644170905236,0.8956615688265369},{0.9127507526214523,0.8986794996280564,0.9105067126308102},{0.896210865213626,0.8907574135676124,0.9164954891973294},{0.9123064513435859,0.899881737765292,0.8896533603427998},{0.9140851976111544,0.9166423673795131,0.8932032133453122},{0.9003358288480267,0.9026827285637172,0.8903685436396158},{0.9065588797985622,0.9017819230293461,0.895920895684272},{0.8937426285460859,0.9117868620419923,0.9066320467969113},{0.9050729403542314,0.9278363184031903,0.917188267652202},{0.8950118196950431,0.8991717582216009,0.8931878302812809},{0.884878603883767,0.9074671755400475,0.8842159258980766},{0.8889077025229607,0.8921336901357146,0.8977687231460286},{0.9077685989584042,0.8937442433408949,0.8903341401250009},{0.9055113290064635,0.8878237212111836,0.9129055846596376},{0.8812969366643854,0.8988070457055308,0.9021483365422607},{0.8974744330122316,0.8936373945849518,0.9065588020988384},{0.8774231391138826,0.9140441671486382,0.8807391486522967},{0.907205570337712,0.9022020477940622,0.917592199538094},{0.9039040852814987,0.9014779228629054,0.8937450485789907},{0.8999596364247652,0.8912639033576476,0.8991275083403965},{0.8939136925211116,0.8949840627703944,0.8968852097682568},{0.9063003343131136,0.8923672944262226,0.9127918061975739},{0.9104753431028755,0.9152984662552205,0.8882132431544726},{0.8910489968192263,0.8766033031215656,0.9074228026671798},{0.9159730023302689,0.9023423356036164,0.9101281852291299},{0.8966701536202579,0.923156887416302,0.8963584585678898},{0.8847627466395731,0.9142952492682441,0.8989602870451804},{0.9012124798587082,0.9119746503342104,0.889387985647679},{0.898066902689358,0.9098336020764188,0.8999086962130582},{0.8952688674424728,0.8987312140426896,0.8915167681212371},{0.8999567121801053,0.8828996143050417,0.8872510512697368},{0.8789928853467343,0.9149488095689625,0.8976764235513623},{0.9042162170331284,0.8858082643592871,0.9109768604276164},{0.9032310396119103,0.9109411572837786,0.8952517684270568},{0.9009992538703273,0.9083294069690743,0.9082367211606273},{0.902557358981517,0.9081224305634052,0.9059302245451655},{0.8960534637486771,0.8965549260055834,0.8912190113554497},{0.9012520195421115,0.9007008105705763,0.8782931179784765},{0.9009803140031497,0.9163027023638584,0.9006625199417698},{0.9008827099408191,0.9103238287776115,0.9111889765280861},{0.9024840151544838,0.8921172082349845,0.8958472715352909},{0.8877303853456328,0.9088827834236229,0.8911167145368682},{0.8865231127602596,0.8926619668834374,0.9020855157335591},{0.9030707749347305,0.9078339265673131,0.909006373080903},{0.8915632122558513,0.8898558237023394,0.9220394810356917},{0.9101654348547598,0.917420944644701,0.9264029074671046},{0.911072668464858,0.8880098464869218,0.8956021302864744},{0.89829911259412,0.8911595857565126,0.9013367916392406},{0.8957812290429786,0.8970129896764785,0.9040311792114569},{0.8943879505451622,0.903791524251974,0.8881760999516204},{0.8984155776559254,0.8932480475091585,0.8954193535917843},{0.9145475049929729,0.8804830300688347,0.8926692524862909},{0.9018747790601755,0.899530038972929,0.8906995094153146},{0.8995571199512775,0.9196690059787608,0.9105732408937893},{0.8953815772498439,0.8897203378668348,0.906995012358065},{0.9122271006182122,0.9039192642514673,0.8887325350914168},{0.9022096612478451,0.9008153275385358,0.8881262106222061},{0.8928086401496926,0.9033812457273841,0.9128112227812056},{0.9054017813224952,0.8972480607151435,0.8939709882531642},{0.890404068655709,0.892620966962649,0.8960540346332037},{0.9063107576308053,0.9028699637403776,0.8925753669417485},{0.8890676179356676,0.8831301019124227,0.9124379337988792},{0.8966333424075099,0.9003612371344741,0.9166054827964497},{0.9056642885815945,0.9126989041361763,0.9099239589842348},{0.8836171717080307,0.8995600281054585,0.9054458619000451},{0.8992594165327961,0.9139922798682514,0.8880673041227312},{0.9053307929468394,0.8958693291578431,0.8927289283309998},{0.8832370952927867,0.8823637824104311,0.9053927299107424},{0.8983211616936946,0.8915964049024442,0.8973102552689564},{0.8918163071035101,0.8999158626550859,0.8928568148157097},{0.9074276855971086,0.9034782538179971,0.9082018764243345},{0.8983747361592352,0.9078527697569689,0.8912600530028539},{0.8838730776672039,0.8861299916814708,0.8883750352847969}};
                char* data_str = serialize(kirat_data, 240);
                printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 4) {
                int n = 480;
                double kirat_data[n][3] = {{0.9033400025775008,0.9096836838301326,0.8960287273632367},{0.8939284730012987,0.8967046982194571,0.8932646738745934},{0.896240067124019,0.8859223617168985,0.9007358551140943},{0.9002475894560177,0.9004734259099111,0.8856908886532514},{0.9011191300534055,0.9118576212386734,0.8894239365716425},{0.9024047562747853,0.8918791664257122,0.9034958391478546},{0.8945393274761206,0.8986813005061798,0.8973934506716731},{0.8902926027494359,0.9147485478816213,0.905809839151806},{0.8839770085869113,0.9023445606105638,0.8965238987913363},{0.8905399748654224,0.9030365607000178,0.893882401205877},{0.9031434604229814,0.9019844106035659,0.8910790557010434},{0.9149324645497244,0.9240129153431297,0.8992530596397379},{0.9128238162278993,0.9107813371784416,0.8996794747719029},{0.9011499371032721,0.8859189345095186,0.880032969302732},{0.8934826652190461,0.9093079957530288,0.9080346885794747},{0.8944593761428625,0.9002452134623403,0.898687042263903},{0.9080133001556712,0.9024047478560169,0.9122867599136},{0.8952339143032081,0.8894824813543557,0.8985805131446064},{0.9110436590981562,0.922109310488735,0.8886097566821279},{0.8906403526725202,0.8756412284062426,0.908027719283827},{0.8994008568411305,0.9110297496301996,0.9157448966875517},{0.8935862233963585,0.889333539431248,0.9039455013078707},{0.889474172914667,0.8952263432082755,0.9025147668512964},{0.8885259990539581,0.8992312563942602,0.9012139514416235},{0.9022900680551041,0.9002723512763483,0.8992209039140479},{0.8867457473494103,0.9000186727119754,0.9003130043611683},{0.9112873435881899,0.9164285891108154,0.9064393760598846},{0.9059082614804358,0.8934232226308916,0.9079695437971029},{0.8839109852247022,0.8858618837165237,0.893590091407165},{0.9178049100773124,0.9087973238911996,0.9058281044839841},{0.9068891192784903,0.9012370809857119,0.9136516004418045},{0.8976569848159726,0.9125007545459317,0.8974048174902669},{0.9212945002026803,0.885677973686036,0.8961490126472295},{0.9048563674880519,0.9152210749190087,0.9002454394909944},{0.9026690596900181,0.8939280745946286,0.883656765176856},{0.8926280614295387,0.8931644355537345,0.9081348631031948},{0.8737978475851095,0.8833934586871415,0.8989816789860106},{0.9012513937091753,0.8970494913521024,0.9038616920456243},{0.9057796184060253,0.9114077767749386,0.888147798319771},{0.8956775403606311,0.8987395146651016,0.9103722227196427},{0.8937723689363563,0.9036166887791395,0.9100887462543076},{0.9090592765368296,0.9022308686383589,0.9145053509124605},{0.8986980052471099,0.8900250569867186,0.9047912270754923},{0.8837904626950588,0.912283204643339,0.9082625786700342},{0.907912111470507,0.901997495898462,0.8868283197722197},{0.9020506253667941,0.8999816203302183,0.9158156011466375},{0.911619399074918,0.9043877076242426,0.8832749261417857},{0.892897370835589,0.8784604844600808,0.9001465464221461},{0.9033795610636493,0.8773346077057548,0.8914122574797418},{0.8945438992436939,0.8929557409344216,0.902080038560723},{0.8968361839518155,0.8845330465516941,0.891976172864684},{0.8987496950707369,0.9093297833796226,0.9127909799845126},{0.9037539215964531,0.8957135690194684,0.9135533743630722},{0.9093178192328392,0.9008899031976213,0.889207308575589},{0.9063269818912436,0.8855859552715184,0.900922896164644},{0.8994081065273657,0.891206868388027,0.8787876574413594},{0.9017833205838951,0.8922480746714663,0.9119185237688946},{0.9025991182460944,0.8925130016382766,0.8891324303095349},{0.9020473021487155,0.8757034220899521,0.9131460935715782},{0.915492946763489,0.8998438348168528,0.8902189398293452},{0.9044421604393303,0.9190872411955052,0.9039738030301878},{0.9001417471181301,0.9083957090561927,0.9088782443619553},{0.9042488367401255,0.898440444049883,0.8950446647052475},{0.8903607827441333,0.8986036083691289,0.8892388574796626},{0.9070148462550037,0.9237572935601732,0.9088554231294987},{0.8947698542874891,0.9074745476673015,0.9036736416553677},{0.8974801350478365,0.8839928417048358,0.8958671938924728},{0.8944627541252135,0.8971663877906983,0.8902495760321983},{0.8955391553849816,0.8958130054148139,0.8865210171041441},{0.8945137055887116,0.8921480545959111,0.918890092321787},{0.9084174602983042,0.9001207818511533,0.9133435370051097},{0.9026069462576405,0.8937865483176558,0.9024594696072871},{0.8967102972997905,0.8981302957025028,0.9019486974883685},{0.9016469553239262,0.9078688247312587,0.8983863035329345},{0.9092170988899321,0.8878120443384505,0.8697223592880473},{0.9033602680420998,0.8862680133437337,0.9123860594303298},{0.9005530883887377,0.897139654886971,0.8791998117995814},{0.9123057386985122,0.9130113883116691,0.8963947668659679},{0.8811294731911373,0.8840517160652945,0.8988627006138067},{0.8909608963608796,0.9063512432212573,0.9014741517814608},{0.8957352149883717,0.8941646238992862,0.9093459794082327},{0.9090955935188062,0.8916402774903905,0.8799183696936961},{0.8941442621318633,0.9166525749997234,0.8931675637920693},{0.8824290587823612,0.8922946090659656,0.897918832194182},{0.9059905970711941,0.9073893395116209,0.9223915221641095},{0.905835814993338,0.904125794868661,0.8917784050513156},{0.8978766704436484,0.9056328322592903,0.9205378177232953},{0.9181012510859746,0.8832098720184463,0.8917501984765283},{0.9050049695433848,0.9088740143059919,0.8750535410420401},{0.9189691347244221,0.8967229816175336,0.9012452236202535},{0.8976337328782388,0.8876827429720341,0.9022589226829957},{0.9053991123335509,0.894208532250061,0.8907536943440022},{0.8784407468234199,0.8843514894543332,0.897565212784847},{0.8926475173901878,0.9096159638742408,0.9008765605181172},{0.8988608215991356,0.8883400840608001,0.8963510077048209},{0.9217754704614256,0.8980238504531541,0.9083008475917351},{0.9006599201261062,0.8863455556961513,0.9090164238368702},{0.9158525833795323,0.8949894771267106,0.9003936318446478},{0.8847867576641004,0.8948811736084984,0.8791447079907041},{0.8941810907337691,0.901769259218723,0.9054437211672435},{0.9027949243532722,0.8897757684274725,0.8938189805981382},{0.9202096886437571,0.8903105489440863,0.9133710363719955},{0.9140044397741514,0.8918062149261344,0.9050806073669904},{0.8905338971924655,0.918288496118058,0.9108372553002114},{0.9137451422356657,0.9058408478078762,0.9117093668374168},{0.8847860190526805,0.9038292161360996,0.8924467280039955},{0.9068971853946196,0.8937749215889039,0.8847062101669279},{0.8868766193627848,0.9006039307934823,0.8985843175899593},{0.9022486293470307,0.8964927996709551,0.8900204496571859},{0.8888391725727132,0.9082650199890075,0.8945535328533963},{0.8867823986016371,0.9112912299637247,0.8781380258207316},{0.8829660236170641,0.8921234408399588,0.8839451651993792},{0.9004625241270349,0.9046643593607384,0.9170143542448378},{0.8905067924384495,0.8987406234009033,0.8832184377289835},{0.9005041481924746,0.8914372847056226,0.9020799156331977},{0.9181725135600892,0.8923040601813547,0.8869316047962058},{0.8905658069563175,0.8901664930943695,0.9039722235723425},{0.8994239644406251,0.9033879072697482,0.8863996160696268},{0.8977040632457196,0.8980992268043421,0.8998085421067039},{0.9034350383399843,0.9039913653700256,0.8831575135215473},{0.8830398446035724,0.8966737296233719,0.8838247781303743},{0.895143411994777,0.8957274322823019,0.868323313534637},{0.8886324406853973,0.9015433317713392,0.8870719738709327},{0.8990228938750189,0.9059464124641406,0.8966195564804056},{0.8968099028403972,0.8891735093992843,0.8994870355696879},{0.8983360055093764,0.8832599976122582,0.9161830000008571},{0.9095610989962776,0.8933004856406259,0.8914702687263284},{0.9113562247593814,0.8958728974225577,0.9136003650196247},{0.9092818542284086,0.9094394252140298,0.9004503057204337},{0.8887548896665364,0.8989939747589071,0.8983567775652559},{0.9144129412242812,0.9091036894426956,0.8867997185534114},{0.9076786398081497,0.8799770253968254,0.8995436790971839},{0.8907722718912526,0.8736653907448164,0.9013343181357502},{0.9051444448000551,0.9026335416229062,0.881405177926582},{0.8885795979202408,0.8918534941150338,0.8826000854299046},{0.8917919096446696,0.9120987297332885,0.9035236347539809},{0.9016945055649573,0.8908682127632771,0.9038275068280041},{0.886953851555593,0.8977318126018178,0.8995009466236084},{0.9101138029101243,0.8836616482794609,0.9040146585140783},{0.9049515289487674,0.90249724008331,0.920200191309958},{0.9020310442784285,0.8941918449898735,0.8996676617052743},{0.925412433054792,0.8948705829767476,0.9049765746951541},{0.89582219969824,0.8953599797583376,0.8991935164369897},{0.9087622700878771,0.8978226562176924,0.9071634538011367},{0.8820376251772764,0.9065997985191756,0.90722886140835},{0.9112445943509728,0.933556476811091,0.9093178936895383},{0.8859353049261374,0.8975845357022422,0.9195942700598531},{0.8927775957267423,0.9115498925859764,0.9048571061001112},{0.9125245268561408,0.9186663167379484,0.8932879276684614},{0.8987682477653987,0.9065424535396839,0.9199794116285508},{0.8891604301354664,0.9114817768311162,0.9060053400637401},{0.8846230335714508,0.9033618481520846,0.8918391912104031},{0.9072797493279976,0.8882736616101998,0.9150434590308308},{0.9037209073404672,0.8941944344963788,0.9027854882258055},{0.8930781537321529,0.9046123134336201,0.8995115282129951},{0.8923207391867773,0.8909817072135786,0.8936895254856075},{0.9075679556625675,0.8982393997993662,0.888654796523116},{0.8994162863072825,0.9026288457142573,0.8837286339012455},{0.9005706885956235,0.9002642750302794,0.9130690811249457},{0.9028860836855279,0.9179825812063683,0.8954260661387308},{0.9194763004352628,0.889147309383078,0.8934644957846075},{0.9013829526673477,0.882377737642096,0.8982758408968321},{0.907793467249833,0.8975851453675279,0.9102571331064888},{0.9162613030564626,0.9067732159934435,0.9078490402162686},{0.8973262315187492,0.9050393028246267,0.894128097560102},{0.9094667879577545,0.9058308147202998,0.9090238375912949},{0.8934835607772214,0.907339657742276,0.8884162461700547},{0.9076389187723768,0.8928605402265137,0.9012439889455778},{0.8886948727265437,0.89676763761597,0.9003970296131004},{0.9167674305434603,0.8821193461853492,0.9095337898498753},{0.9243394854666284,0.8982964428003158,0.8953559303810306},{0.9001064331454894,0.9002454118078255,0.9175028861221629},{0.900833344276423,0.8890646720467009,0.8936703068429552},{0.8805501455794558,0.9024523282827646,0.9026210736546195},{0.8873529608334387,0.8953007316896465,0.9019667691591621},{0.9136307735486651,0.9082137885779117,0.8974545436780215},{0.9237636805593904,0.8823829678606355,0.908226385420504},{0.8903197887073233,0.9060075116464291,0.9059805571860813},{0.8940968429752422,0.9190831992488362,0.8812366747973108},{0.8967363077191393,0.8948460308777896,0.9084359761363919},{0.883074357037469,0.8988366309815142,0.8875823294092077},{0.8994933124390687,0.8995814800289403,0.8901803726040416},{0.89247518248036,0.8958528963465716,0.895017065596921},{0.8966464359133445,0.8747890869258858,0.9007654351702504},{0.907898606675779,0.9068597411523216,0.9001053204789049},{0.9165671830246953,0.9047152273659794,0.9047814474874094},{0.9167781902769488,0.9124304905339603,0.900740128806404},{0.9019343779800583,0.9005242393901082,0.8762039476263168},{0.8899540196746696,0.9163382472248692,0.8995454419563177},{0.9081968219397307,0.8967168553670092,0.8934666414709586},{0.8936209367395834,0.9220751660474532,0.9061022278747567},{0.8970048305972628,0.8930134126884346,0.9137176275127232},{0.9092336426194403,0.8909140487197122,0.908855977606266},{0.8980504305764502,0.8996443871733908,0.8983187874954878},{0.8726295947789176,0.8868320599545152,0.9099539956216225},{0.9206383859357223,0.9043117860540902,0.9053912043358433},{0.9105602811725404,0.908889564192027,0.8974205051220293},{0.8781480889770464,0.9016657208076587,0.9071357701117841},{0.9127108326988601,0.9122869972722855,0.9173874745328833},{0.8932606188578196,0.8962845402670295,0.9008999732868428},{0.8937720881232016,0.9040672514520477,0.8915050870369289},{0.8938684284167032,0.9217796435663395,0.9142873144120556},{0.8892721792445338,0.9176988409233975,0.9130242249207284},{0.9049712645114891,0.8993177718108979,0.8986173525412989},{0.9081239560240755,0.9124309412891465,0.9113751875466221},{0.888965554550939,0.8936612868184314,0.8952730426802629},{0.9136808608536685,0.8901387854624906,0.9089461539229544},{0.9177419086382307,0.9038807791039614,0.913236185167901},{0.8986639941002095,0.9059646080721622,0.9035803982147237},{0.9041594343594179,0.9031321371463708,0.9093618773872739},{0.9112759054516146,0.9197460135701937,0.9098040099967024},{0.9045549683745289,0.8997506326151785,0.8940023730580068},{0.9127828178555759,0.8850873993096613,0.9002537470891104},{0.8951910363989596,0.886056615987285,0.8992590696445213},{0.9083793878441802,0.8962378527901453,0.8930597623799628},{0.8805119033653706,0.9051005940968632,0.8889859732660241},{0.8964756410378628,0.9077202097660151,0.8817747058115734},{0.8922101976205085,0.8986804434739089,0.9176333032556154},{0.9036168412662929,0.8937854548887821,0.9102364905943728},{0.8979189363640356,0.9131204255141718,0.9167808330837818},{0.9090510784473432,0.8968019597779049,0.9129482581646503},{0.8808885243254612,0.899398042889761,0.9129080758518375},{0.8881351525417254,0.9020755842516719,0.8982561314407842},{0.9039488945399952,0.8869498471241001,0.9165051987389068},{0.9154613318574198,0.8923518935137627,0.8919602025214525},{0.8912309289061571,0.8842632350943429,0.916160464321897},{0.9068165315781126,0.8942624556780686,0.9004630249882216},{0.9026124830629658,0.9091940331035228,0.8968412021003692},{0.8982388584429808,0.896191137065849,0.8972135593391884},{0.9012039608579389,0.9013021013148431,0.9044189505510826},{0.90246098144164,0.9031275133714824,0.9003952470244654},{0.8974124551898152,0.9102222326847247,0.906621973718608},{0.9154073412410805,0.9071621189799863,0.9067809879254042},{0.8995141019007699,0.9130071251797158,0.90926892705295},{0.9142490285160524,0.8909806293170868,0.8929881458072587},{0.8989733337868459,0.9079153615794895,0.9055369680985573},{0.9164388152925818,0.8911715671920666,0.9152173971795171},{0.9122026718293783,0.8903960684647284,0.8925143020397305},{0.8990625268962694,0.9027283828021877,0.9111940462831841},{0.897210556847307,0.8999182255350129,0.9128730294329545},{0.894960720942754,0.8772292293147395,0.8919687595416871},{0.9046129643840479,0.9003846730994047,0.9006811591745164},{0.9060304508520096,0.8856241165395841,0.9019133222954215},{0.902168089899575,0.8901586614847022,0.8925840056980618},{0.8974522480476578,0.9015776863413376,0.8865819902409847},{0.9138132619069148,0.8977962408842973,0.8920493041696829},{0.8881056720447498,0.9107941346448247,0.8976772912789966},{0.8930381350496729,0.9039182271779678,0.9084667067533795},{0.9071472343613693,0.900505801436831,0.8971142009414163},{0.8861363115053454,0.9155083695791337,0.8956785039144153},{0.903674108625652,0.9155090641999315,0.9014485549113097},{0.8991190030637315,0.9254374666249777,0.9211448901841305},{0.9056436345259743,0.9041476599111229,0.8853639981278316},{0.8802113826924043,0.9046891862504803,0.9068269580052375},{0.8988228464840813,0.896951551590916,0.911077044341164},{0.8837019102647573,0.9136235492742285,0.8890068950291263},{0.895992536565241,0.8881990052326392,0.9010024472272714},{0.9254349983357184,0.8818534631527598,0.9062948243149023},{0.9045486786838337,0.8965135100669156,0.9062958355485218},{0.9037132608480297,0.9004057985345496,0.8965252156405378},{0.8850690126479124,0.882257776869706,0.8817098123859957},{0.9111395072207819,0.9055675027014827,0.9187800585228559},{0.9035536789202973,0.8962039414993833,0.8864148811345073},{0.901779996866573,0.8836967411897636,0.8812495191147698},{0.8759557339319766,0.9016594999228408,0.8897530503060941},{0.8977725490446561,0.890473472515467,0.8961042187858931},{0.8949183501932725,0.8966417346949878,0.9127858586827858},{0.9205463723492799,0.8927985648975885,0.8920655597969491},{0.9080846516606415,0.8962472371351949,0.904776756097836},{0.911847493188469,0.9085055554827762,0.9010937246184985},{0.9034480300013258,0.892933222441013,0.8848653697696994},{0.8996185298964605,0.901267877380406,0.8902794618360751},{0.8928114786538522,0.9165457705018917,0.9060262491726301},{0.915302796960836,0.9124396020395154,0.8922297958288399},{0.8955376914396852,0.898811791269052,0.8932761321662396},{0.8901802933346246,0.883670127930623,0.8993577169960584},{0.9190155163639939,0.9049830307250935,0.9057280517174238},{0.9087606216404726,0.9034186142358976,0.892393629300243},{0.9143541312615197,0.9114168975181068,0.8923027907805992},{0.8984912715621598,0.8926719672048713,0.9054160174541608},{0.9049758053667964,0.9077013248174265,0.9131873330767292},{0.8987668438879828,0.8814993055200906,0.9027122739534883},{0.8864689609630649,0.9068281810927477,0.9067177105212403},{0.8873000152579192,0.900604334621726,0.9040871144666073},{0.9051041369391298,0.8917915110333892,0.895633749362559},{0.8969181509638784,0.8877039642278749,0.895821637941802},{0.9046224401266681,0.8928571895916159,0.9145229205257402},{0.9018458637647707,0.9077132940828202,0.8807003902756088},{0.8972258095630625,0.8930872324107106,0.90060023750249},{0.902149729496976,0.917943483092631,0.9021376822319278},{0.9042329054869035,0.8913812250832905,0.9023515746622549},{0.8688577644137634,0.9246979395906373,0.9074615435572609},{0.9061982794689947,0.8987045728656684,0.9004055705620868},{0.8939615508606886,0.9135432118780024,0.9017842233317035},{0.903968210302678,0.9123222249663031,0.9122721725448653},{0.8792919834900854,0.9119166550213595,0.895022673582683},{0.9011382262241006,0.9158580069665198,0.9207251248765838},{0.8923009436769813,0.8865141843123967,0.9025612467102756},{0.9006733977351081,0.906797401822721,0.9069739630602431},{0.8874991417400454,0.886448106781629,0.8981655973006404},{0.8999195444516307,0.9089107568391961,0.8974404164755913},{0.9023318616225788,0.9166522001167879,0.8996203528525996},{0.9051636813458641,0.9024582141552608,0.898010699667238},{0.8930996913108986,0.893491388925478,0.9031204345108802},{0.903199428276963,0.9160199909003754,0.8909982052542934},{0.9100588938380635,0.8870576964531456,0.8950945250503122},{0.8925144245040763,0.9030880970880348,0.9025229278370315},{0.8935226483090848,0.9057975950671671,0.8957552509967862},{0.9059502471559714,0.8898273323939944,0.8955279706219466},{0.9135695740431458,0.8977213435519501,0.8946435790351226},{0.8992040737721942,0.895932735867722,0.9087255313477154},{0.9037124152354347,0.9053839298525803,0.8927025723753513},{0.9141656142732887,0.9087047102729507,0.9017248658623537},{0.9103625541615477,0.9014777529180598,0.9184261126946109},{0.9142055328292809,0.898997596391687,0.884337178229692},{0.8946892008535812,0.8987968514070259,0.8989369128739776},{0.8917447280258997,0.89996604930802,0.9092257380724723},{0.8986507938141965,0.8896968125856133,0.900207399475689},{0.8969484200341719,0.902972210019551,0.9060015815971505},{0.9019660980147687,0.9034841899470637,0.9080069385518845},{0.9071442653862466,0.889831462350777,0.8935957052101521},{0.9152205332527861,0.9000008306378583,0.8981920624133056},{0.8812485102197767,0.9073457532847782,0.9070777929358358},{0.8797238793169798,0.8727030753883338,0.912014209063412},{0.8885122880669517,0.9253460688373543,0.8977126509227257},{0.9158844041836275,0.9018203604666749,0.9031707453299381},{0.8954709541305677,0.903984400651298,0.9013328959631443},{0.9018852007855408,0.9097343982781774,0.8982946680078778},{0.9004731784132727,0.9045862940359778,0.8786704720586564},{0.8920545399966548,0.8974086696705595,0.9181023982832639},{0.8824137368233208,0.9080095185598079,0.9097594217061901},{0.897195087489931,0.9027606623353895,0.8882293014770335},{0.8948204783992112,0.9107436315359917,0.9126088497830736},{0.8993773906873909,0.9020130772918379,0.907342890545414},{0.8897224058967761,0.8902661431320492,0.8908740157070792},{0.9074111401083729,0.8909259287615348,0.9002484978208958},{0.9076110614127719,0.8895232651994104,0.916207343791412},{0.9007888586107351,0.8964486617691038,0.9186664929517642},{0.8881810713462169,0.9000514760624284,0.8955408759505791},{0.8792939495489998,0.8874263272492501,0.8983172836542792},{0.8966959812184546,0.9069832078537192,0.8917563779868941},{0.9029736000828659,0.9021913378002778,0.9065799282887677},{0.8870450447717423,0.8802900596440888,0.8884633438610975},{0.9249749069964498,0.923856096686852,0.9074151579958251},{0.9005309839307958,0.9039771660041964,0.9063581273323552},{0.9124563890913221,0.8884856463245645,0.9142141932910438},{0.8997148115060261,0.9090532040850624,0.9040095388185203},{0.8979465490398718,0.9017891659130467,0.9030081626537664},{0.9121893950605608,0.9063020970757818,0.9035149072896511},{0.8927319736397701,0.901947489051825,0.9037708420246029},{0.9031885494088098,0.9046763933721255,0.9101552089828423},{0.9077520317117752,0.9067863446469012,0.8926556748059185},{0.8865350372732543,0.8760280639594888,0.8931078373899048},{0.9054691223177371,0.9163912339398268,0.8977158156200769},{0.8961536141874153,0.8961077655063231,0.9077237276131115},{0.9234738022548995,0.9053151731018001,0.900994503181885},{0.8968319625813523,0.8913416168221227,0.8845167351990747},{0.8946756228792959,0.9064469655708065,0.9022011557812869},{0.8885816020111215,0.9000501168776153,0.9023536555200738},{0.9102334823588448,0.8961742919458201,0.8841066754312197},{0.9029646817533689,0.901040747620332,0.8996064394861936},{0.9095082735604918,0.9060786458812695,0.9012004415751469},{0.9096786803977716,0.9042258423095859,0.8893618220113119},{0.8987482890367127,0.8851081997505443,0.9001267057530289},{0.9037223440756673,0.91371993687514,0.8925637186886706},{0.8984899417626173,0.8959775154096276,0.9161989986984586},{0.9032895093191697,0.9078304741336285,0.8950334658071938},{0.9176663923407135,0.9039630272534347,0.892389923776432},{0.8989546875383635,0.9099579715785207,0.9076117706034887},{0.8897087865726934,0.895278927651909,0.8974967963572387},{0.8822975154843092,0.8905744554764492,0.8951430108658973},{0.900885846207373,0.8923508904162706,0.9015157949412068},{0.8902312505280856,0.8931965870286616,0.8848322416347382},{0.9048281207268412,0.8946612664452079,0.8980696834106795},{0.8878555430358955,0.9010159579854452,0.8976888474974889},{0.895549375284769,0.9051473944016657,0.8960410859082607},{0.8979907847237946,0.8997413244334768,0.9095896446158236},{0.8926148014927384,0.9036202772895847,0.8962925116234094},{0.9032407730550647,0.898689320756611,0.8997953876508908},{0.8991347090295783,0.9004265153410648,0.9032740468677564},{0.9042409920377775,0.9038257100804802,0.8852872873519685},{0.8933930091998642,0.9205803485343823,0.9023512738677311},{0.8884652129011358,0.9153045766757101,0.9183387459314739},{0.8951786241222809,0.9103791944520204,0.902704062972186},{0.9051009045624281,0.8977038150410027,0.9007155742177874},{0.9011754976804747,0.889751465221867,0.8913288316863577},{0.8849439141061824,0.8897386045787535,0.906666735390926},{0.8990633387247602,0.8877410520460043,0.8949026743670013},{0.9152547849375776,0.9065569933901546,0.9010030124567442},{0.9135385326678116,0.9048342205509597,0.8979263156109704},{0.8889461194955441,0.8980524607146474,0.90329452477841},{0.8848056254849046,0.9026367811500805,0.8905900924999484},{0.9056150799658632,0.9150452588668149,0.9074639074677934},{0.9076590276038324,0.9089836002198493,0.8962311967553065},{0.8959841560563566,0.9058777930705626,0.8997801470223401},{0.9081953405859872,0.8941963605272236,0.9058905438876009},{0.9118744628447957,0.9085470286506695,0.8952259415131114},{0.8903286089393102,0.8998808632828187,0.9027735199908616},{0.9096601451766677,0.904440573016912,0.9001081711651294},{0.899902904995623,0.9093579927591785,0.9107660874058807},{0.8853826642185201,0.9074158805925526,0.9010987673878278},{0.9006179713443699,0.9118659071036425,0.9021463778236402},{0.9081628167864377,0.9112147621968254,0.896821968511225},{0.884050584421132,0.8913019451762589,0.8898726681103948},{0.9010839243930855,0.8982282312696692,0.8856273632029124},{0.8865483053753737,0.8989615177726553,0.8838770718096971},{0.8916666026286482,0.9097481508422539,0.8952312866890769},{0.9072273592887619,0.8991230516921065,0.9153966788158594},{0.8998816120623409,0.9072547402317055,0.9092034347848585},{0.8961409537720156,0.9147611067588921,0.8885927122827818},{0.9109530225117367,0.8920121054067855,0.8957573306479885},{0.8788763357568017,0.921480536902752,0.9121237546999652},{0.9020407826081613,0.9027496560839583,0.8973398703744293},{0.8873313126528171,0.8932226847432049,0.8910903057375714},{0.8969299010082399,0.8976435024950383,0.8926910043596353},{0.9029157482440345,0.8987950985601141,0.9018142862836727},{0.9000524303755795,0.9148757565533703,0.8993351642934431},{0.9099813215236612,0.8965897084873833,0.8979962215837356},{0.8877954691698395,0.9179366223056437,0.9052754467212982},{0.9064532051201016,0.9147570078297297,0.8879322098852389},{0.9207498235906433,0.9038837256390914,0.8851127763063052},{0.9051221208713818,0.8824778212586923,0.9081559717490909},{0.9026209996282588,0.8745325994576578,0.8982586204024099},{0.9079958226222141,0.8996271641827335,0.9019204645840654},{0.8987964722757151,0.8838484790148939,0.9100133831698989},{0.8935498258377674,0.896686582219555,0.9051991129108828},{0.9129841536891389,0.9032108710215503,0.9173130037285903},{0.8864674667643102,0.8829180840379582,0.9020015158820144},{0.895682180522498,0.9303407752848096,0.8956506175721732},{0.9145938570950682,0.9061239802626688,0.9102240356133261},{0.8903059594652462,0.8911781711430972,0.9229208089388214},{0.9005976476800388,0.8829673502374544,0.8924070350012836},{0.9117462940256925,0.9085507431023181,0.9076671871776354},{0.9115166967570661,0.8891479279494976,0.9159251613666204},{0.9015946066407989,0.9120469311082678,0.9016379547568367},{0.8953939489733177,0.8863388241546559,0.8876198802067778},{0.8823821562171726,0.8967572959066004,0.9195410053679891},{0.9244950359786227,0.8943796963024684,0.896753641691902},{0.9190823406489856,0.9139415405264996,0.8952079942447589},{0.8920877005823752,0.9166229033589391,0.9105284118965058},{0.8969558083019298,0.8856940281271687,0.8884560249466352},{0.9175349726950625,0.8976657967572746,0.9021509863677843},{0.8969568383698003,0.9260334461299482,0.8990887467206595},{0.8960499513686622,0.9196659712442623,0.9058907952160181},{0.9028878758752369,0.8982396201486322,0.9250462723303845},{0.8854138089607284,0.8968977323589802,0.8937372796838994},{0.918427753519333,0.9051097002581084,0.9090638760475327},{0.9044151995604065,0.8903175261105485,0.8851032912152863},{0.8963861627384155,0.8903234446772867,0.9123330832804698},{0.9189025721360174,0.8976697964236738,0.8855486742552632},{0.8981171353835528,0.9060813919973751,0.8989693314563041},{0.9165876123593651,0.9093961955653473,0.9097163792253674},{0.8944469415573814,0.9055346495948343,0.8987446767552433},{0.8958511026548963,0.8858813999117712,0.9068848678386063},{0.9003517699471302,0.8970728529521175,0.8993046867478908},{0.911445034102464,0.8861552098420331,0.9090696163936521},{0.9091009571313919,0.8968064756847982,0.8961387626174337},{0.9035986617762046,0.9000533256090906,0.885885450892355},{0.9030505155408467,0.8968859233907392,0.8844664925431588},{0.9143962608820825,0.9159879018858689,0.9017232172017415},{0.8974313139076309,0.9049618355512424,0.89829667391621},{0.9100899726986311,0.8928968700264821,0.8978892902419434},{0.8861480370104973,0.9034840137703279,0.9000113595355004},{0.8950961769152568,0.9099168829218746,0.8826181860621983},{0.8860757201295948,0.9038665303424944,0.9043074632311326},{0.9056418730312726,0.8929724845561103,0.8974223828314984},{0.9074729221321204,0.895380330298698,0.899847338452325},{0.893591277462777,0.8971589470966419,0.9092429379797694},{0.9181147537656963,0.9086835115133185,0.8972709610643728},{0.8812987685943491,0.9113925220935609,0.9160568987300323},{0.8940543959559573,0.8961372208185555,0.904788214541507},{0.8913001525826517,0.8961983004937887,0.8861349967545721},{0.8921640512724714,0.893636303694717,0.8862815839448109},{0.8968587920200015,0.9376069083592172,0.8957949436663406},{0.8946274312428046,0.9079819898430754,0.9094215641902619},{0.9192352259840381,0.8933550806114992,0.9143637568558576},{0.8866493920794287,0.9195816243135349,0.8874378277308379},{0.9112885393559603,0.9091261540879709,0.8900969263412862},{0.8971155227164451,0.8989192789193866,0.8920237536152028},{0.8841589933519818,0.9078479642527006,0.9010814038286332}};
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

void bank3_start_fn() {
    enclave_start_attestation("KPS3", 1);
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