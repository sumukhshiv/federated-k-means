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
int bank1_sp_ra_proc_msg0_req(const sample_ra_msg0_t *p_msg0,
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
int bank1_sp_ra_proc_msg1_req(const sample_ra_msg1_t *p_msg1,
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
int bank1_sp_ra_proc_msg3_req(const sample_ra_msg3_t *p_msg3,
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
                double kirat_data[30][3] = {{0.3030697873146271,0.3030697873146271,0.3030697873146271},{0.2808936723034907,0.2808936723034907,0.2808936723034907},{0.30367809608796614,0.30367809608796614,0.30367809608796614},{0.3030199074031139,0.3030199074031139,0.3030199074031139},{0.31090633263350614,0.31090633263350614,0.31090633263350614},{0.3103354725841466,0.3103354725841466,0.3103354725841466},{0.2995354973029857,0.2995354973029857,0.2995354973029857},{0.28549467898513614,0.28549467898513614,0.28549467898513614},{0.3054152011984239,0.3054152011984239,0.3054152011984239},{0.3069385735651228,0.3069385735651228,0.3069385735651228},{0.29824512406138876,0.29824512406138876,0.29824512406138876},{0.30665682664420885,0.30665682664420885,0.30665682664420885},{0.2988424061307112,0.2988424061307112,0.2988424061307112},{0.2794963569295213,0.2794963569295213,0.2794963569295213},{0.2992941535538154,0.2992941535538154,0.2992941535538154},{0.286211787003142,0.286211787003142,0.286211787003142},{0.29074483572365967,0.29074483572365967,0.29074483572365967},{0.29327592413520487,0.29327592413520487,0.29327592413520487},{0.29636144567073214,0.29636144567073214,0.29636144567073214},{0.3012000270054786,0.3012000270054786,0.3012000270054786},{0.2880979854939783,0.2880979854939783,0.2880979854939783},{0.3137333451886978,0.3137333451886978,0.3137333451886978},{0.28811863018280026,0.28811863018280026,0.28811863018280026},{0.3048730309374213,0.3048730309374213,0.3048730309374213},{0.30512167668129586,0.30512167668129586,0.30512167668129586},{0.29617565574822113,0.29617565574822113,0.29617565574822113},{0.299647369535345,0.299647369535345,0.299647369535345},{0.31451993611543266,0.31451993611543266,0.31451993611543266},{0.2973065162953068,0.2973065162953068,0.2973065162953068},{0.2974672951598521,0.2974672951598521,0.2974672951598521}};
                char* data_str = serialize(kirat_data, 30);
                // printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 1) {
                double kirat_data[60][3] = {{0.3142093372316209,0.30506120890229244,0.3165745708048303},{0.29049690018267366,0.30395555335684393,0.29287484737030156},{0.29722201641671103,0.2960537682981844,0.3075425155658386},{0.29147111579524615,0.2932247816658737,0.2837579948564971},{0.2989204690409145,0.30315848065429685,0.29944485694373185},{0.3006194342032125,0.2930199166770289,0.319567397440054},{0.3056947745584098,0.30454759313385094,0.28901037025559373},{0.27833316190582535,0.30034043870220156,0.3011596682774395},{0.3019343058139876,0.2914894289741829,0.3082692607419702},{0.29720594699063757,0.2884326040683274,0.2962591884760742},{0.286763548051873,0.2905457068997479,0.30589512885377207},{0.3096271244045328,0.3039159994496861,0.33577145467723535},{0.3195044851466244,0.31253244124173507,0.2903925210501493},{0.3140467038933651,0.287997914617531,0.307959840622558},{0.2991650244999074,0.2871572841343863,0.2946998649022167},{0.2970297405146693,0.2967826411987782,0.31143335130624555},{0.2814899191500585,0.3042138775167097,0.325238290431807},{0.28392683667524404,0.29864803266626727,0.2834658022092389},{0.2915461572634054,0.3154017888845473,0.2951723826997787},{0.288374856395146,0.28818598659322686,0.29372892101807624},{0.30244338415462585,0.30922364470273456,0.28450589734342757},{0.30745293794514716,0.29886378731188734,0.28211628887607276},{0.2947961791956877,0.2990868937329485,0.30217054293962053},{0.27992752133269927,0.2928350867964572,0.3106335030293142},{0.2863450359410051,0.2995528349270242,0.2966210727071841},{0.3142453716759401,0.3064073262059349,0.2834418531144738},{0.2873191814632529,0.3073123282460967,0.3017519036420466},{0.3173432966191118,0.3059846263629054,0.29956563247957796},{0.31499097543103244,0.2932130190777408,0.29740417809430825},{0.29568006406183983,0.28791115152659236,0.30840969044377325},{0.29576888193299944,0.3047270284091879,0.30314722223002255},{0.3043839663436889,0.2998612711768496,0.3059382087871695},{0.3035844823172112,0.2786053049499405,0.2906261588438913},{0.3013551966713251,0.3017546854576281,0.3006206750583824},{0.2941527553559125,0.2868326034557112,0.30227002320325097},{0.295690386679342,0.31313945846988767,0.30851816623376016},{0.3036370820131493,0.2867327198891721,0.2914127217722545},{0.29429084081177415,0.3014481100440142,0.30181085882431563},{0.2945224656142742,0.312300323062676,0.299763180733182},{0.29890167845324384,0.29782745893411733,0.2936160766728563},{0.30069289293618706,0.2973475112832355,0.3062792182160929},{0.2970683766648272,0.31275904975073515,0.28958742741473203},{0.3063302415078314,0.3066837427220845,0.3129428612133578},{0.3053571050550121,0.28639215196324846,0.30620231149461585},{0.29886032862120493,0.2907116117187402,0.29221177863769354},{0.2978260687175073,0.3005853813634351,0.2977313982637081},{0.2994256970027729,0.3000781807993989,0.2960198723294169},{0.3121431469205947,0.3152118821017613,0.30905763909098616},{0.3037770929074728,0.2957456748259446,0.2950880146792404},{0.298271963489489,0.30738483128464983,0.31037088285221326},{0.3047680364495558,0.29491425102911917,0.3000213422170484},{0.3017502593671617,0.30571013150955906,0.2901166247283019},{0.3071392489194361,0.3027490840727584,0.29299022381923817},{0.28962553509854616,0.33004982616904055,0.31628818394174646},{0.30295570889805906,0.30159917486469007,0.28641441027875736},{0.29525447797212495,0.3060574308147187,0.3083166222237095},{0.2865787875199075,0.31608335287097533,0.29921223159874416},{0.29493352337470946,0.3199604959358663,0.286108978271328},{0.312320988598705,0.2993371486383123,0.295255070441094},{0.29316090768768516,0.3008771077257401,0.290737314549109}};
                char* data_str = serialize(kirat_data, 60);
                // printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 2) {
                double kirat_data[120][3] = {{0.2989605728889498,0.30901628118078217,0.29074740207271044},{0.3071527124477209,0.3182029905407216,0.3101622368556477},{0.3065603135909487,0.32528861523010844,0.2906641071765896},{0.30012265702690666,0.2955771474468622,0.28228306703328443},{0.3040156733666294,0.28910601742001407,0.28878221438727447},{0.2886099510641557,0.3116254050149655,0.3019996197910434},{0.2758665253194451,0.29744466196695335,0.3169229138655933},{0.2726220758819019,0.3018239406436858,0.292666645649557},{0.2954034445606716,0.31119682073202837,0.2982889777044733},{0.30435732092547585,0.3144514956770088,0.32298930343424653},{0.29770558798543767,0.3183798896064158,0.30709685536013737},{0.3058176045081763,0.2950261711723775,0.31497230361666095},{0.30342604173287885,0.31828129168867697,0.29376051799319325},{0.31503468846467964,0.2913503351605343,0.2982090050395093},{0.29568500586686747,0.2956575157114562,0.29127267812419916},{0.2958588085119484,0.29569020217164455,0.3105176562006605},{0.29791865275763085,0.3007699124877467,0.2865896458377631},{0.2973148726189802,0.2988601282689432,0.3006644668785747},{0.30293618553132445,0.30877106828061884,0.31065886397313514},{0.29226985387314364,0.30146382949989337,0.29398209927173197},{0.29139606662958173,0.2874019331324435,0.2984121110855756},{0.2896230244378106,0.2834297973297592,0.2986820622767418},{0.315685255133251,0.3082172070445523,0.3061189857487186},{0.30523439514838996,0.2865674967274876,0.297214422312834},{0.297789701799375,0.2896760664235986,0.2819565825971799},{0.2966696836731635,0.27762918939418707,0.2888734941788468},{0.3053147455002616,0.3016439053498028,0.30668956472277215},{0.3053933646130877,0.2901569441130428,0.2750136845377922},{0.2893653970653956,0.2994064771481792,0.3078955960754784},{0.3035191644916504,0.2970436218461471,0.30285841605325386},{0.3019674598053858,0.3076991583193651,0.28908412687385643},{0.30857090275337656,0.3220538997566632,0.30135070680395415},{0.30899919817290133,0.298978088256263,0.2968083988470054},{0.30559015146953367,0.3182004162124905,0.3040663954069119},{0.32867496114218125,0.29580236080805433,0.30332242674152526},{0.3069194575666622,0.29251928404868727,0.3007031445803064},{0.28980662639268473,0.2838736119777049,0.30428150266976683},{0.29759519333093193,0.2826517518955845,0.301598079136063},{0.28927066809451885,0.3045316264750083,0.3148481885697227},{0.3129025489092991,0.2955072510991202,0.3117878269687503},{0.31483986527194185,0.3059475122196725,0.2975661338213336},{0.3085560616829108,0.29157429774227706,0.2978297801534127},{0.305142784969543,0.3002566747557706,0.29635217412329534},{0.29751857204338866,0.30087494718603197,0.3061230483200331},{0.30349162105296185,0.28583946472620736,0.28932274485410564},{0.3109811016829317,0.3028405265952557,0.3006857696771087},{0.3109142555018388,0.29134321862986445,0.28436709079686573},{0.2915427321541276,0.31179090110106067,0.30669379398398794},{0.281872873502833,0.3007167010615741,0.2958392791084251},{0.30649588915524556,0.3058313224843791,0.30239784664369324},{0.28923213478872833,0.30280730035601433,0.30046096035517245},{0.3033237203668287,0.313543938911067,0.3049827467658702},{0.3081239729105739,0.2954540373629513,0.28840399254523436},{0.29386803223669833,0.3201097912025618,0.29332167048743857},{0.2894039523975041,0.2885752352652378,0.3061260009369342},{0.2901608458345193,0.29004883651212343,0.30629718861957134},{0.2948930713435228,0.311700880784959,0.3157505884451407},{0.3110243585852001,0.3031958777195481,0.29355339739320946},{0.3073934656871417,0.29659913942817523,0.2932297952760081},{0.2885691644718855,0.303048857066202,0.30963980349268416},{0.309399366372428,0.31343743914717276,0.30970847757455683},{0.2920128246479972,0.3116236342527767,0.29914658854949555},{0.29092455897790503,0.2968738069750293,0.3069241743118588},{0.30625235088771124,0.2941517465834751,0.2917024169554706},{0.2915952029333751,0.2955537712421324,0.30173561145768324},{0.2897540164523177,0.28215306959023995,0.2964420090753583},{0.2917401800278571,0.29742112515112956,0.31283574759632027},{0.27772009388163865,0.2952106949140099,0.2991805552801513},{0.3021173079245968,0.29153113327179964,0.2986008824935458},{0.2973185954737411,0.3026544401050959,0.2899986527923713},{0.2862499293167672,0.3090619841684912,0.30873822518000116},{0.29663874921912836,0.306239220464539,0.30346710616760914},{0.30269042844770094,0.3123711661355523,0.30067024840607776},{0.291149271480885,0.2987729403527426,0.30862391456817384},{0.294909944287452,0.30140089426871425,0.299611396974543},{0.29766098244802036,0.29520758847713735,0.2969593413659426},{0.3146526643789931,0.3103992880049572,0.30051445599290744},{0.3004459755176692,0.2967293062421078,0.29941402692180347},{0.2956745567330224,0.3148046184673358,0.3016094389024752},{0.2933513475396325,0.29994351417064885,0.3163967520398433},{0.32116688185293996,0.3011133169698565,0.31240887876795453},{0.2847983336939623,0.28515065985107474,0.27772531863515776},{0.31918278376766845,0.30871910329067814,0.2807451230401032},{0.2936777638813542,0.30070086193827605,0.29942012587514405},{0.2925250257691232,0.2886613933683358,0.29477127229648536},{0.3029546081719906,0.2963833386692096,0.31373904423737115},{0.28226752358330087,0.30682209305151326,0.2969548731530011},{0.2954482186191353,0.29375630019602933,0.29738583541906666},{0.3125352032319182,0.30930012550873864,0.31589192332794425},{0.29652482664988894,0.2941089933619943,0.29663549845031856},{0.2967047757222679,0.28989287102376654,0.2942084144853989},{0.30857926173622013,0.31096743309424185,0.3037297522293554},{0.29600137208639915,0.2949446190547239,0.29654021267145597},{0.3089943960071767,0.2971280734952162,0.3019409446342695},{0.31958335274182725,0.3131728184713584,0.2900691511368489},{0.29606956675390067,0.3009209765634182,0.308744855316566},{0.29787377933193054,0.30015833436144146,0.31150239972616833},{0.30306287571254986,0.2979574427851844,0.3043265940926741},{0.2940135128711449,0.28200696594471436,0.29302736534615703},{0.3080617227193861,0.291305410380283,0.2928947751171622},{0.3234797209656999,0.30279219119807743,0.29486200405945484},{0.29975568679939835,0.29382931628801195,0.2979108242943241},{0.3271667603783238,0.3049823405618413,0.29207340079546606},{0.30303959998372926,0.2854809723146778,0.3143625655982456},{0.30035275558815905,0.3013892026023272,0.28712094566705565},{0.29890617511639983,0.28779242418859124,0.30336035835446334},{0.30868125881217234,0.3008580788371305,0.313016891010213},{0.29873937061890526,0.2923205393492504,0.3154985809729529},{0.30906626019157535,0.2802870160462941,0.29511752033733657},{0.28763976325724305,0.30260068143157515,0.2930096932361367},{0.31028492791687756,0.3444116923241297,0.29489717116869324},{0.3137645179253562,0.2902844301800123,0.3068060216406317},{0.30132153931412226,0.296979086280896,0.31575711590990824},{0.3129901729872057,0.29972676243959023,0.3004969827628286},{0.3059144127101273,0.2980532404832464,0.3043987102385894},{0.30210809145122264,0.2988578409613598,0.321528504296116},{0.3182737753410703,0.29556678713131745,0.2966650560427864},{0.29711938927602344,0.2998615019125506,0.3016741656549992},{0.3116028022661104,0.2963158618944446,0.2959236433692045},{0.30874369144949604,0.31646880960416107,0.30306422324188254}};
                char* data_str = serialize(kirat_data, 120);
                // printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 3) {
                double kirat_data[240][3] = {{0.30669794571038816,0.2915542943151976,0.2899491528818442},{0.31526962016002963,0.2919335568573317,0.30529699140902367},{0.30720296528004176,0.29799352144822056,0.30017416035357763},{0.29254761910112065,0.29669391580440485,0.2912363259262418},{0.30945253277987345,0.3121659154237981,0.29952261787729834},{0.30841163013194517,0.29340913131279167,0.3031054035383627},{0.290281542812766,0.30584841880311875,0.28840880125848606},{0.3047746805038531,0.29793581406425346,0.30061469280455455},{0.3151036346335301,0.28244707705522343,0.29968289628194006},{0.30893986307820326,0.30211119203089604,0.28295134220004886},{0.3076565350606417,0.2928335423821827,0.2863108331238664},{0.3002159453015997,0.3111822735614935,0.29670830373901225},{0.29285651571235793,0.30085882103485406,0.3003786763565206},{0.28367502278795415,0.2948143443496122,0.3102822296987496},{0.3084445702797354,0.28998492489638517,0.2959575299773424},{0.2942339969750879,0.30382391872734427,0.28879672530822514},{0.29519502335314246,0.28694903451513515,0.30091566417691795},{0.3082042158633696,0.30381494605496384,0.2939306132722651},{0.2920293121467981,0.3034192624664799,0.30345647342963616},{0.2932249082769042,0.29725616761492446,0.29794966667591155},{0.29364571303286113,0.29822046378351336,0.3010749477048168},{0.3014690266919676,0.30783798382078786,0.2941581103711884},{0.279026022096325,0.30557867155224033,0.3100927831840631},{0.2943667407415865,0.2941551631878617,0.31827228584793726},{0.2950650580942648,0.3146276920635745,0.3058951564172083},{0.29881413628411085,0.286442325921375,0.28376336616902376},{0.2960599566547134,0.2949359786293606,0.2790615197641342},{0.2962729134303813,0.29298805927129223,0.29879234458115034},{0.2773644629578382,0.28527200744122316,0.3098560685033981},{0.30927300296785654,0.2940803630389669,0.31103603930224344},{0.30465779784186797,0.30647624883749836,0.3184467817667667},{0.2759382487392437,0.29633902664033207,0.29367409526520544},{0.30489033999913917,0.29646033781899883,0.30957055201937345},{0.295744648458915,0.3153592697782579,0.3009482951118828},{0.31343998205312623,0.3086901255104472,0.3049637966116972},{0.30389128848908326,0.29773053164872365,0.3013593220514196},{0.29469111273092935,0.29316358877388243,0.30106536563532804},{0.2954949566157891,0.29466901343083896,0.3049796694901234},{0.29921623518157237,0.30276043102369177,0.29633446308121464},{0.3046454640171577,0.30858986628966295,0.30443671765477054},{0.2942017040683983,0.29085655179358844,0.30901889477427263},{0.2826539530635745,0.3068666338654577,0.3109899470509859},{0.28639042055874503,0.29666483798940757,0.2878765531030984},{0.296137504875921,0.2886593678819532,0.3140466684051009},{0.3070574850151873,0.2987113320590575,0.30925557580988666},{0.3068484140179074,0.3102310288931447,0.2986522488620167},{0.2837416840629282,0.30250055461987696,0.29230224534678},{0.2949736294750647,0.3099902033810277,0.3039295872925147},{0.31106439003034053,0.2985732520050643,0.3045177502003836},{0.3118125929855792,0.28615421653873035,0.31242199152727107},{0.3020166344143446,0.3096877694687111,0.30447863443667744},{0.30621406780035954,0.2876016341271812,0.30587113564705515},{0.2977465160975505,0.30584089248474616,0.2907731177893073},{0.31366587647160754,0.2907830639871982,0.3041771340912304},{0.29887843206362186,0.30183682955605107,0.2931604327129746},{0.2856766222771725,0.26820146648269755,0.29118927041924403},{0.27687196711874945,0.2989178527066757,0.31133335000489687},{0.30717939974517794,0.2933938686059341,0.2958030580753839},{0.30333035008578446,0.31001951858315724,0.29907326331232204},{0.3109514561994753,0.2972361026767763,0.29378835747126286},{0.29048622047947537,0.2896940015392278,0.2953308267058842},{0.29352152633762285,0.28292214330348464,0.29258927235183263},{0.29769058981827146,0.28907099567354405,0.29677817357936054},{0.2928966999275164,0.2981792460140724,0.2856367313510603},{0.3021754354357403,0.30561269667812313,0.30958394443754744},{0.3066005786276006,0.31572529481804046,0.29299328604065683},{0.29677890324041356,0.30388532367971466,0.29958927136073626},{0.2931515966287881,0.30844875745170963,0.30792086732700763},{0.2877677117069554,0.2883602112708751,0.31898586731217765},{0.2855479371577108,0.31427752444141854,0.2810355960839122},{0.2943705333905802,0.28142539457250926,0.30046421491178915},{0.3028430209959939,0.2950178535525277,0.3176061261875341},{0.30563853143863157,0.29590465513659403,0.30638471477803564},{0.31213679965325514,0.29979705255168626,0.3001540264785929},{0.30918961812448087,0.30799939650089236,0.2907601958555337},{0.2859192708868825,0.2879438055803991,0.29652025169574936},{0.3139813839223201,0.30159525294598605,0.30154538232203065},{0.29616413475234077,0.3015897995302248,0.30486074659521883},{0.30174621134893864,0.2871495427426999,0.30292924609977473},{0.3057472415360587,0.294308152825965,0.2801024174086613},{0.3133728726861108,0.3032541815709137,0.3112984663217722},{0.2913719839852694,0.2939835762925283,0.2950134566963294},{0.30616017408616475,0.29937136862145614,0.30710432725065284},{0.30731475075557346,0.29295952891937005,0.2912809973030198},{0.2996715994789249,0.2936305677243141,0.29016665738974073},{0.2967156010554529,0.30435593800886873,0.30993387303385794},{0.29830906258991485,0.30526578095167944,0.30435176701868427},{0.2945164465781809,0.2970926418868044,0.3095896873508294},{0.30491889434765823,0.3082104127608002,0.2864597355369043},{0.315250260856761,0.28358628402030894,0.3075092074465571},{0.30473403809774274,0.2960792284087928,0.3128421273887388},{0.2957434870603329,0.3162948385852792,0.305838979832089},{0.3138478896377683,0.3066361975472536,0.3077598206186826},{0.2979618621485744,0.3049108464911979,0.2938762603927074},{0.29116887292591537,0.3020917002136669,0.29119366415784936},{0.2956984960021519,0.30793932760541,0.3039298956875627},{0.29056418856068833,0.2929720171803111,0.2950863560038005},{0.2867851338728941,0.3014646922691606,0.30619222035444715},{0.31032990713990133,0.29255992550603327,0.3139622983284493},{0.2866078371404002,0.2980786921282171,0.31679294340120806},{0.30671227938252393,0.31384785917118885,0.3063472260613422},{0.3146361958883986,0.2828792119862917,0.2977278344806343},{0.2945750709800162,0.31025458156127333,0.2847570265040063},{0.3226253359173422,0.3102415044379377,0.296084239104448},{0.2774529232005782,0.29158075616277274,0.30288665649418367},{0.29509435817782753,0.2882264069529675,0.282662405657929},{0.28861020883267946,0.277362275569911,0.2878901089259039},{0.30490765098563344,0.30047518839625076,0.2961699264029691},{0.2898906592957151,0.2925333013644458,0.30273592590184284},{0.2870025881024029,0.29428640933511113,0.28756907601416914},{0.3065052401208415,0.3090293141949056,0.31228963150831857},{0.3029189419932066,0.280595893816835,0.2988829103428599},{0.30104356166351165,0.2886397110137408,0.30730809400518944},{0.28946233175881436,0.306741966483972,0.2863779033483419},{0.31558596605654027,0.30243265621144255,0.28897552809922245},{0.30963576502434365,0.29467037261190276,0.32234973975721176},{0.3164228406798325,0.3102719156311649,0.28449925299389817},{0.30274553341679,0.2795773197206897,0.31641307775396393},{0.31411546483443054,0.29195020511411723,0.295447285296675},{0.2953625125296015,0.30039636519164226,0.28196535938055894},{0.3135320699333597,0.2916317167762807,0.2835691308505709},{0.28288784683211354,0.294773097690484,0.29683897487095295},{0.3038313665713417,0.277281222722802,0.2897131634586474},{0.30127145799130767,0.30356910066359083,0.3081782098704974},{0.2948842168214221,0.28403445935959576,0.3051462137665416},{0.29925409121342444,0.2982703861680932,0.31701610943725667},{0.3005670597115622,0.3009065601081187,0.309864012616901},{0.3069360683528203,0.3007859362608199,0.3079356626369123},{0.2924089742650812,0.29808119633339125,0.3060679721222405},{0.30391622935042034,0.29831288167129416,0.30370657952810387},{0.30503890810025946,0.29354264689170384,0.3180055216788221},{0.29259314479790244,0.29682520221989445,0.3190163588142584},{0.3018132645006368,0.29795925842151105,0.3065396587211696},{0.3132315722373224,0.31261551708601343,0.2729479679978616},{0.2979167636766488,0.2891397805622819,0.3158769103941556},{0.30288817303222154,0.31188338176221503,0.30369983303507364},{0.2879712642143161,0.3016496416899993,0.30660074546732474},{0.2988271601925678,0.29174069260088936,0.3042875440634026},{0.288398125207441,0.29288593335797936,0.3095754779844595},{0.2818855892235071,0.305050784480178,0.30320069735103167},{0.2971605672837502,0.28908104892004804,0.3145555951900705},{0.30823349971508507,0.30532826639516064,0.3039904490018061},{0.31670502028651476,0.3022805780378101,0.30727409799406713},{0.3107518783832011,0.3023106698041515,0.29649429378995507},{0.28728564645074395,0.3020603231748682,0.28689807592266514},{0.3111292065617967,0.2970520693419865,0.30590523631046057},{0.31016123975324456,0.302922927869868,0.28336743034049516},{0.3042681594103796,0.3028598259667647,0.3045848964767627},{0.30776916070997196,0.31828286998530375,0.31737079218189185},{0.2941640344447099,0.3112298819828328,0.2897653159946748},{0.2978667046701399,0.300118279668916,0.2915345521067297},{0.3150352921675997,0.3012886818714616,0.2925173542283934},{0.2844736153949926,0.3040131703263884,0.30797546947370164},{0.2952714207540133,0.29387935313659974,0.28187833914385335},{0.3045328283890372,0.2968636536631409,0.29762011356531465},{0.2953513237293012,0.3014929667267573,0.30315246710671534},{0.3041591294177414,0.31994705306197774,0.2999464157046219},{0.3035734088927893,0.2978103873528915,0.29884000931661536},{0.30620559273069964,0.2845288594005694,0.2927879482220901},{0.2870467352025717,0.30677302065266665,0.30278797582471684},{0.3107477508237792,0.3047398118037065,0.28945944451258604},{0.30056745923781203,0.2879976293220126,0.2999200599290556},{0.3177476035289917,0.3121260966846264,0.2838351288333048},{0.30332723469741046,0.2937370368546527,0.29164389781015826},
                {0.2966551512802705,0.30206871401814916,0.2962787064591812},{0.30106421437140307,0.30205791009927463,0.29994363715331757},{0.3022345350291171,0.3047478002121877,0.31187424136532976},{0.31155540701289014,0.3027724010250162,0.2934760808292096},{0.317207942714758,0.2956941995504334,0.3066855748203468},{0.3119429534439825,0.32092660937432504,0.29985742952153194},{0.29242933857125325,0.29190056970135814,0.3067314535079233},{0.28918669772868566,0.2974556625459112,0.3011759323193276},{0.3054757553064277,0.2980192644580941,0.29521003518203426},{0.2962335982473661,0.3196663395631996,0.2940868711279951},{0.29149927015120264,0.2776638047015326,0.29403384624972273},{0.2850759366203295,0.280443964215606,0.286673191860033},{0.28239548592816827,0.3004449606414536,0.31002415897439306},{0.3007316370320778,0.2866368026786677,0.30174730362592544},{0.3091876305544265,0.2957135580266678,0.30701472740392344},{0.30380002016079694,0.29351188679387563,0.31208063669464214},{0.2922834170781596,0.28367544446554716,0.3007431179724628},{0.30964666643000616,0.30441006864260256,0.3161092554850337},{0.2995829602321453,0.32086667302245464,0.29740766940587043},{0.30720593400822577,0.29086459086096283,0.29798736692414185},{0.28727407032842733,0.28702721756269894,0.32310766931354584},{0.30384473834006875,0.29162596007199176,0.2911929866261138},{0.2987445249228822,0.2937753055670455,0.3151779786156143},{0.2874941635276672,0.30152790981669897,0.3066883886687109},{0.29540748693038954,0.28164340064950444,0.2978919364456841},{0.30975526380690516,0.32591863702125107,0.32766240997163043},{0.29578218977876164,0.29936228675147636,0.3049493450691602},{0.3073878857370787,0.2991870314516186,0.2910125116369451},{0.29960039354249324,0.3005915862880544,0.2979417655835639},{0.30520373597988554,0.30129407446524886,0.31133546620932995},{0.2948287787110229,0.2878842416511159,0.2917495305196349},{0.30212037065517466,0.3005375709311835,0.2901676997668885},{0.2933018402703239,0.29856063465872207,0.28993846311935895},{0.31736665910053297,0.28189653142385973,0.3132789586517013},{0.3022455514790713,0.30883163107104206,0.3138434968929461},{0.30727144037060694,0.2996837833285659,0.30871848861586576},{0.2958587452521889,0.2937364982878936,0.30290098512576397},{0.29425180661625605,0.30316165931076117,0.31290960160279163},{0.3041663671776048,0.3063718989834246,0.31308587665369436},{0.3193035348164391,0.31380574209073847,0.3022668791312044},{0.29491808712854,0.30759532388623617,0.2821849776885571},{0.29495401243824926,0.30953569555618243,0.287635131459768},{0.30577397272588347,0.28875836010951306,0.29730800125507073},{0.28996503648181365,0.3156414710705827,0.29432361821787206},{0.31335467339181555,0.30647544354145995,0.28106093810070176},{0.30281213190227635,0.30657348601488943,0.3254021876403364},{0.2832311156455302,0.30406138754989176,0.28787669478472716},{0.2941512715556533,0.3019326021608416,0.29648357977088624},{0.30946210761235426,0.29925557278571957,0.3055791296630277},{0.2988240750673187,0.3091410948292577,0.3035852360508744},{0.31765264204258203,0.2777778543999975,0.30664016878845124},{0.3118424548738895,0.29522925123335614,0.3015228456646757},{0.29186337976496046,0.3024248939238351,0.3025410358780493},{0.3025085844742261,0.30058118260649797,0.3050288895599226},{0.2889312102837387,0.2795159540986127,0.2934832676867024},{0.29485705008901814,0.28259829220551613,0.29942265279813846},{0.295057841277781,0.31981438155251785,0.2988426398590091},{0.30995853577361837,0.2836965140480233,0.3054955246252351},{0.3245229200509321,0.28408276874830957,0.2931596433577114},{0.2954704785248003,0.3146652622757061,0.2934073889142843},{0.2952118381462519,0.2876183358093269,0.30550577996998957},{0.2989016634797543,0.2887023998688223,0.3041525357735516},{0.29743170499742944,0.29190015767128374,0.29368063298946984},{0.30978478663755976,0.3050890021895176,0.29238942972340104},{0.29412725413716734,0.2885929118038737,0.2894064439220408},{0.29355565395141014,0.30996468004728533,0.2857484247622898},{0.29879888584909525,0.309524478455794,0.31918942013107987},{0.3024557454774112,0.29916019024741475,0.3033492265820086},{0.2899679301073313,0.29498957746951215,0.2899872565577559},{0.27566193865435046,0.29881031000235075,0.27285477382360834},{0.29802361651412407,0.2862579439051097,0.27714705867119666},{0.29713536856056555,0.2936732626062023,0.3086158676585382},{0.3149625327993601,0.32030991517403207,0.2928415171253902},{0.2941858513011826,0.30331508748833536,0.3085043717874632},{0.2856959927628646,0.3132316653623316,0.29781939086646864},{0.2829226440722387,0.30564054057940415,0.3129705689514323}};

                char* data_str = serialize(kirat_data, 240);
                // printf("KIRAT !!!!!! : %s", data_str);
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

void bank1_start_fn() {
    enclave_start_attestation("KPS", 1);
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