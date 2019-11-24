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

const int SIZE_OF_MESSAGE = 30000;

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
            } else if (TEST_CONSTANT == 4) {
                double kirat_data[480][3] = {{0.2864041609751514,0.3077803631091051,0.31084492047569956},{0.29619654950191227,0.29014058471094045,0.2982753621144072},{0.3003803472322903,0.29449773557199227,0.29601320553514715},{0.28798825806323897,0.3017960642114968,0.30926977437586517},{0.2967906121096622,0.3143154195978978,0.3036185986567091},{0.28563185653974105,0.29958732569053476,0.31877073648274956},{0.3015701422109654,0.31381341839761895,0.3040217565428135},{0.3094034826046529,0.31156856893177465,0.29785076120412624},{0.2980948014123361,0.2907818277555831,0.2754420033315785},{0.32056342126431914,0.3029179898927203,0.2774405363565941},{0.2927808129825695,0.3086664779147365,0.296210859577034},{0.283493485937041,0.28287896206972063,0.2874828221660018},{0.296447009865178,0.2940632678155867,0.3018277156040432},{0.30236163323097104,0.3045548705921276,0.28866986884205487},{0.2953685415359009,0.31589465655286614,0.2969706037929696},{0.29557978200304746,0.29937370469697766,0.3072065943759752},{0.3153741212672629,0.2949536402696402,0.2893100051020717},{0.297292974664131,0.30889450935703316,0.299790853635609},{0.287448899807089,0.2848267498389656,0.31713727225448896},{0.29679911630760764,0.3112685774237045,0.3210487139175285},{0.28916692896037727,0.28626738690833065,0.3024203829700211},{0.2717276823691003,0.29017404401595975,0.29805910806238656},{0.31759707952604355,0.29518278456294533,0.28627834055571605},{0.30241983962040336,0.31942970189989306,0.3026309811780334},{0.2988714883198027,0.32254880492775406,0.3145777343180178},{0.31371839071488905,0.2961831486438948,0.30279258584767177},{0.2948764510903685,0.31168566256224495,0.29882199064489634},{0.2870920589863996,0.29384247037324623,0.2819762874733313},{0.30583244864956444,0.29834271967350884,0.3069629502030821},{0.30612053225690283,0.3009370174805251,0.2927615431492245},{0.28496733423889675,0.3185521138061959,0.3098844046087683},{0.30169760067958395,0.3018137230121557,0.30360354100495657},{0.30155330409442027,0.2914467475103008,0.30264004475843925},{0.2891595378301807,0.2950991441198832,0.29548976804682797},{0.3161134025974443,0.3113451349864942,0.30805538955586015},{0.3007667673922008,0.2886841785094453,0.30204327418424626},{0.29088908061613095,0.30425010607556424,0.3068174379835184},{0.31605217237744365,0.2942517079485397,0.2820936190243053},{0.3155849976571838,0.29522082407392086,0.30208521931155713},{0.28421593675974033,0.2999539365816148,0.3003598557542821},{0.31170362787567324,0.3130774281511612,0.3089050106633736},{0.2824739437920777,0.31614884228333767,0.2956412104753767},{0.28780706454182625,0.30913050376657913,0.29637083474686926},{0.28593379642721084,0.3128385674837229,0.2963443770879978},{0.30645172748747046,0.3003450329679085,0.297399576351684},{0.31030419479496785,0.2783234927669185,0.2800453788882815},{0.3151118302624115,0.3080456324456085,0.3090518311839907},{0.3000551806223602,0.3065449716233628,0.31101386233342543},{0.31252164153445045,0.30947857468346185,0.30480930069767176},{0.3205015068639798,0.3202206363730296,0.2973807866832612},{0.28644576482716316,0.2989808645472066,0.309290353335513},{0.29781355513300806,0.30135383134168237,0.3098762419507576},{0.3101867397947451,0.3002851492493479,0.30282295512972174},{0.2969006435819399,0.30227391251029445,0.3026914175522346},{0.287289445829518,0.29262942530157293,0.3082880709559369},{0.29816860226013936,0.2980353778996906,0.2928720063516779},{0.2955387709858949,0.33878477440165455,0.27856412846319406},{0.2914749764411066,0.2969581954213169,0.28361608522837906},{0.29863339299938896,0.3115641859365859,0.30037258866168587},{0.30698353461383027,0.29605082967477014,0.29291184893986966},{0.2941489524485521,0.30194224136615416,0.28806093223064977},{0.3086218525271663,0.29809134469685067,0.29134152221075127},{0.29024779905308357,0.32325572318647133,0.30580599192749475},{0.282385028204935,0.31326535155552016,0.3025842591387869},{0.2920813148541395,0.2826088889007054,0.2996083354330258},{0.28248244869661715,0.2946062844311538,0.29918357166793597},{0.2814498503087928,0.3013088415436233,0.2981822773911302},{0.2972096904504014,0.30127277303812383,0.3037196290449084},{0.31355008490021713,0.30488528154733907,0.2917805850998194},{0.2950021599199713,0.29806180934884596,0.3303767591209658},{0.3113781751745122,0.2934394493562934,0.29305381514584994},{0.2819456278683554,0.30634703498795135,0.2972089251146474},{0.3101680343338606,0.3172437869807102,0.3089669397821422},{0.2943485480040989,0.2979678072042452,0.29215533740330235},{0.3170629053408612,0.3053528913855781,0.3140258310438819},{0.3198493493517603,0.31248339746689385,0.28941941704772856},{0.29742167595818386,0.2946409646227,0.3102496416600734},{0.30893295034482404,0.32164256030283706,0.30692452440154155},{0.28990818276394364,0.28978159936745795,0.2902251681595491},{0.290473119102221,0.29419320053495557,0.3007691395653778},{0.2896992086465726,0.31698670163951725,0.2895991383556444},{0.3013962767700265,0.2948616760441771,0.2928358210511167},{0.29018330315451296,0.3130829450756312,0.29053235860334137},{0.29264160113186394,0.30350880165935423,0.308950070795297},{0.293749913596756,0.2938569099210787,0.30551188263694834},{0.30850480983017864,0.2973974145159574,0.29148638868376525},{0.30545549893769836,0.2805126968184896,0.3107186567198098},{0.31758450578056835,0.3023422503271233,0.30303928425887633},{0.3078605846123034,0.29457205189100794,0.3215854483040163},{0.29341883867941665,0.297589718762054,0.305748118502911},{0.32041204547068436,0.3058900821599471,0.28491420528089645},{0.2960182328857493,0.2921225091064906,0.3122381380926558},{0.2958144270898782,0.2918111703041785,0.3004123885193285},{0.2970129238329021,0.3013271916953425,0.30099682217019436},{0.293684431463186,0.30632334640395725,0.3081771451773736},{0.30112795469277764,0.30112599218145103,0.30353496141266995},{0.2946068484968464,0.2898209738566717,0.30506562268205034},{0.3017272885718796,0.29943371429940757,0.3033532553424986},{0.30165760336848907,0.2997838189362196,0.30451933613138227},{0.30339568759491947,0.30833991071246153,0.3067930396817708},{0.3007361863718356,0.29329750525386367,0.292964468708799},{0.298360386659992,0.3195351836687681,0.3036637278903876},{0.2790814919625721,0.3159048775451511,0.29750299483363324},{0.30849765662998196,0.2860358793046437,0.3064564865134866},{0.29556671835282505,0.3071991932042671,0.26388819998341423},{0.3027855875996954,0.30443404629915527,0.30745934883225445},{0.2992366927628993,0.2990834284330836,0.29258772967608876},{0.3031485517957938,0.28358667583150976,0.277347281631048},{0.28791595415364074,0.31048863167415114,0.32577882001886516},{0.30731499843798554,0.3019433123367423,0.299876155950005},{0.30950356416110625,0.30070449892594636,0.2858747254122985},{0.3001681380890442,0.31035565362271406,0.31160452358950624},{0.3200612011157913,0.3226596278148077,0.3144718485175272},{0.3100563489822423,0.3057710773254155,0.3213580488652016},{0.27699680789392755,0.2874445313570323,0.29307194543623094},{0.31966524222489845,0.29832962654371514,0.3173159055090968},{0.3101563541626157,0.2974697614033728,0.3053699347154386},{0.28889746128231314,0.29887607691178203,0.3094547572420088},{0.2919203646338765,0.30242110039328585,0.30083141627235316},{0.28656381998146846,0.29562509482513855,0.3129811255174718},{0.30433795030838096,0.3004623179457185,0.29590147217659213},{0.30072170313939306,0.31111366451229205,0.29755669628224596},{0.2824406319653827,0.29683002393762065,0.2903487684532476},{0.29856347255074106,0.3147651202324542,0.3050009876181099},{0.2864533648150463,0.3113862177753913,0.3083900849040183},{0.27934025813278635,0.3021996525231848,0.29261738255301023},{0.2941616672379212,0.3199624285750018,0.3024851521187718},{0.32747070287033025,0.3182086820242269,0.31235055266921347},{0.2908984588278732,0.29727050175569864,0.30377378168453967},{0.29326015225965113,0.30861339734775106,0.312750441305264},{0.2973558025210344,0.2954526605497708,0.28531739320428373},{0.29173477726204977,0.2982095378708833,0.3147756677058651},{0.29814907124207773,0.2844479018257208,0.28762908172905716},{0.29939068275597913,0.2951027770374721,0.3070119835447805},{0.30751107743676315,0.2944342514508693,0.31099252542348366},{0.3071312364065379,0.292013209451242,0.3067509756283581},{0.30406786428560195,0.29008239335866826,0.3087068950481612},{0.29796016439680284,0.30795714191546425,0.30024171012361495},{0.2941632123389561,0.2905070773251993,0.3159942603106428},{0.3063409422613895,0.3118550676610658,0.28993743522392196},{0.3126120826462045,0.28798265864196426,0.32808736022967966},{0.30144491159998144,0.2805575067070045,0.28584567497673147},{0.29726835488449366,0.3108385418926179,0.29365439644328134},{0.2952703696607601,0.30882311538573237,0.299063006713492},{0.32444089390100395,0.30460436922149925,0.28095778837304614},{0.30630115795275614,0.2974088449446948,0.30521632594623155},{0.30207715414632974,0.29789738462063,0.29377681655303983},{0.2906417130085379,0.3053223448614398,0.29001317131330023},{0.30582125394330917,0.2919316426168161,0.302461491904828},{0.29938384059778356,0.3041184064973825,0.30884923020172295},{0.29835038292542154,0.3059442595846871,0.3086097248435637},{0.2931659578774103,0.2850384062379911,0.31152162024385943},{0.30745742207816334,0.30510415766952786,0.3023351176894745},{0.29414869771382324,0.29448201408770314,0.29973775185601703},{0.31238900347566384,0.319917499910988,0.31019313896548834},{0.2874983630210064,0.3007546576918055,0.30202466119028704},{0.3056394503125309,0.30540161261933685,0.3007099049742385},{0.29551350591656833,0.29030521798328135,0.30949684109028985},{0.2974712500990261,0.32595519471185297,0.31857881313332387},{0.2998676946356997,0.31170442415942057,0.2945802000014394},{0.29299525523614905,0.2993283935860304,0.30200832452539356},{0.2936356079982317,0.29895516983676673,0.29739370974365287},{0.29909481269309085,0.2893121543435122,0.28753069636914913},{0.29970894218503985,0.29617223533009945,0.28419183194163133},{0.3056618530591524,0.3132131378205803,0.28760442387690527},{0.28463196310165756,0.29919740265382305,0.29468902490044013},{0.30176813552692466,0.2853540543680421,0.2935902262685548},{0.309452802556566,0.3204463861565898,0.29044733130056755},{0.30144855841526785,0.2785046481436242,0.31775497677476494},{0.29752049211530307,0.3069097025812242,0.3047879137708867},{0.29908932269986904,0.30323957583042194,0.282632778977719},{0.3023141319420347,0.30330249394740433,0.30532315480523164},{0.2948585743451744,0.3046643030829708,0.2975162597182188},{0.28929449932772805,0.3109932533621621,0.28905024623953385},{0.3056573236338673,0.3033611210755396,0.29680536428278104},{0.297611126756535,0.2991590558687868,0.315133920785639},{0.3035795678897298,0.3104105537814328,0.29301954020576443},{0.321174149809298,0.30643502677964485,0.28126954487203515},{0.30336086764810033,0.3049146265405255,0.30200510509883516},{0.28567499680683783,0.30263450937899483,0.29533254444630136},{0.28638513428007745,0.28559870292758793,0.3016659264464274},{0.2929208473579065,0.29203110992273273,0.3078665820898181},{0.29316233061885155,0.2980538328072991,0.30354884770601276},{0.297865609081016,0.306335839280142,0.29960352701457915},{0.30497763495565805,0.30532701281654345,0.29624619314924},{0.2760129664608477,0.3199061113726358,0.287744869906876},{0.3034423882249404,0.2990588414254448,0.311188535020761},{0.2804899217036594,0.3039781938126346,0.2992127352824461},{0.3115903740164595,0.2994605574109631,0.3190265816674262},{0.3127640592979529,0.2926645551387233,0.29358361625342166},{0.30464059932723364,0.2927702256499046,0.31437062736629784},{0.29439817364758536,0.30923747349934194,0.2909115865464343},{0.3037834051893787,0.31038910935564473,0.2950689547058816},{0.3099236877127074,0.2942036211192648,0.2910345410630723},{0.2971603807913248,0.30180727251887385,0.3073452572924303},{0.3070951882108159,0.30411708640214946,0.2799094779211309},{0.2933454049494789,0.31339770326318395,0.2982971254443834},{0.2954071290445552,0.30831054936734525,0.31263331346998946},{0.28342972212648604,0.2924086634451012,0.2974515347515773},{0.2915451514586575,0.2856887305715213,0.3000117675785288},{0.3012952218200366,0.29153871881888277,0.2992693493480105},{0.28536805545048977,0.31799273048061444,0.32277359866177796},{0.2817273891101377,0.3050706404209459,0.29340462278490687},{0.3095134718749814,0.30689237916586554,0.3051158345345942},{0.31983711303879103,0.31688971120986054,0.2976874401604865},{0.3074452293053751,0.28990867061382686,0.2987100712933744},{0.30946252680549724,0.32087329849676305,0.288486607130419},{0.2990310103670029,0.31940052550442477,0.28578521260387685},{0.28798844206290086,0.3076511662147937,0.3067454382529533},{0.2955238916061532,0.2894433274852911,0.28699601306578015},{0.3050248059842643,0.3057390045223717,0.2858771587814398},{0.29962308621755557,0.30574780751419967,0.29795528161126766},{0.28097874500188863,0.3096213708082134,0.2869907889736613},{0.31519674855936336,0.2981074788292622,0.3034065475700587},{0.3030785876602752,0.3000402824290507,0.2897378190956206},{0.2875172151711338,0.30298354036030445,0.32451920809570695},{0.31358644309854056,0.3066835310369543,0.2751655940125774},{0.2965455862455168,0.3051221076924249,0.2817062710251472},{0.2901866187398689,0.30848391376689,0.2928142019669751},{0.3030301600884641,0.2938373283936769,0.28174214653971413},{0.30472818187087664,0.2994200702912461,0.29672113710146475},{0.3047517860729615,0.31788255846941227,0.2992132623289878},{0.2828758850384746,0.2871644404381661,0.313430311197023},{0.3098285150041705,0.2967944048046411,0.29962954848191026},{0.31547151117088496,0.3151767634597967,0.29071830940817406},{0.2933758660572331,0.3000600039685813,0.314551800740723},{0.2771130350119567,0.29116703849221337,0.31030237963831714},{0.32295217367210893,0.2854739587704015,0.3146272897632795},{0.2977266884385605,0.2980252745856539,0.30896287598258},{0.2943866588511081,0.31284188303248295,0.3117426353744682},{0.31170115543448135,0.29356281945161594,0.31053663196510733},{0.3061553071098204,0.2923700634333167,0.2847450031826177},{0.3014556984634788,0.30697119173981663,0.30183467642433287},{0.29823809364711956,0.305615877290064,0.28748307128034956},{0.30431202029757143,0.31250211381933324,0.30538636466758645},{0.2996663136138097,0.2895657185243981,0.2996781274608423},{0.2872297320502284,0.28278013093641746,0.2956924661532601},{0.3063506092807986,0.32150638118924574,0.2845370093059963},{0.2940614465676775,0.31087364397256584,0.29463116859435606},{0.31046211171179605,0.31142781838455114,0.2971226949104048},{0.3047644411695765,0.2976054233906528,0.2905759434687944},{0.2959925237985652,0.2947287614047233,0.3008782631673627},{0.29550975027657705,0.29293810572084383,0.2941253449017635},{0.30116139906648914,0.29147778952140935,0.30593712484962293},{0.2984290977372654,0.29425663512838296,0.3129334282330895},{0.3031144281332577,0.2985871397336651,0.32552004322320094},{0.30624224889282353,0.3144079395654894,0.2979332846899852},{0.30870341266337487,0.283598916880096,0.29007782151066136},{0.31682342785855905,0.3095718672884649,0.2939498793963069},{0.3112547545235562,0.30359731333525597,0.3056519374559115},{0.29629069826736293,0.29894618155388053,0.2988641981856525},{0.2830399024261484,0.29065056188170274,0.29463068714916435},{0.3064606263919693,0.302170002420733,0.29169764797925285},{0.3024252603676963,0.3158354094189156,0.3004186871979843},{0.2934960529102991,0.30792904326128717,0.28739926891802786},{0.3082366236503254,0.3017691426207187,0.31175538336979997},{0.28721357431921185,0.3088633627729725,0.29213219684227254},{0.30528903466981133,0.2907791886175049,0.30688419856198174},{0.2839532050031669,0.2947661371998427,0.28735976327093177},{0.29212221392646054,0.29753944044617997,0.3066708975546664},{0.30422721431981015,0.2968863824184442,0.31063509616925583},{0.3133700160957455,0.3057357119480472,0.294680073313446},{0.29240142332402347,0.3036395039652796,0.2891689915894208},{0.2917017708500129,0.30447798028467654,0.3169758774634245},{0.28027484556436477,0.3011939421412115,0.29333455851778445},{0.3055246728134322,0.2992930922906059,0.30813547980646017},{0.29905990562115387,0.3020178494993424,0.2881419354527922},{0.303730037772311,0.2977997175269083,0.29138866384514694},{0.3058211520332786,0.30538829016534363,0.2974369679249952},{0.302581091305581,0.3145042371886755,0.30038505260033593},{0.3032130355511909,0.2896781512677536,0.32892191383213465},{0.3134410447618292,0.30222851156129665,0.29891661877658454},{0.29312841449887833,0.2997382870274373,0.2856953838456606},{0.3063940615092901,0.2951297202402783,0.3013670123304002},{0.3041935175736628,0.31199052292213497,0.30256583408244087},{0.3086143373304742,0.3215353459437537,0.2928065540715524},{0.3040493680736773,0.312203246946527,0.299735100137145},{0.28877588918183283,0.2958862222601608,0.29119918243513554},{0.29371359478220227,0.31893009570411834,0.29606103256383476},{0.2933107287535159,0.30021735423360046,0.2904301226428342},{0.3021098197393157,0.30300148425583984,0.29448284223526067},{0.3084774150985282,0.29035854696269314,0.2895782163501428},{0.3078716431986271,0.30536781635258775,0.296345040736607},{0.3019479389288301,0.29320815477211193,0.2948791692416156},{0.30214215419678875,0.2980827813211042,0.2984120392890015},{0.30026232563091826,0.30006916453104193,0.28734272529200083},{0.31681626366280197,0.3090055763431383,0.29368147763847496},{0.2943539755530681,0.31250248998532804,0.29970258119080806},{0.2915802265298811,0.31267921608953103,0.28238553278933776},{0.2834618592148798,0.3012367610097983,0.30627949103580354},{0.3075568503080669,0.3157701364267994,0.2839007184968815},{0.29434980876276756,0.3032458351187748,0.2785278745504767},{0.3082523488096471,0.30976173467485973,0.3058206956222628},{0.28328198122090226,0.2929537240656819,0.3030399568746877},{0.28250489738026047,0.28955517291648797,0.3083392408806596},{0.29305008038128094,0.30832295869293064,0.2997254429111777},{0.29792937731034325,0.2873533556272726,0.316503022774492},{0.28249668229888464,0.30638614165661027,0.29940313799669294},{0.30686750024535486,0.3018559794471977,0.30375743908992164},{0.2957304747682625,0.2862820667116964,0.2995856544011095},{0.2881665533138036,0.29785665171864684,0.3121967170796345},{0.2885139232989102,0.3064279102576235,0.28598266436003744},{0.2900391819744435,0.30762513941154346,0.3138936098241557},{0.3066156990831245,0.313139547629171,0.303150442085296},{0.30093679679555285,0.2853282931256511,0.30880935027700623},{0.29938212849196777,0.3140180270284402,0.2975455895237273},{0.299094327386475,0.2897898249654167,0.2957508033245469},{0.30085262876108715,0.28792690423840467,0.292889906870554},{0.3071722274783415,0.30216683076490114,0.2904101301149248},{0.3086560444176997,0.3121520372645579,0.3008125590817967},{0.3031705974234778,0.3146255288843183,0.30939405020566546},{0.2979211479450921,0.2971430139017138,0.30357769713454025},{0.30138514277272316,0.29677495619924965,0.3234127820414465},{0.3048362243281599,0.2931131643290224,0.2997353117035808},{0.29915673548163574,0.3053819863996638,0.30534029160053155},{0.3164445477126778,0.3076214072937932,0.2981737081897697},{0.3178738074824452,0.31396602195253953,0.29438455796461327},{0.29112090685892505,0.2892178696672539,0.2857257943135932},{0.2888761759536273,0.30879727958971354,0.30619166905388706},{0.30006586801807955,0.3026828516343571,0.2962848087914267},{0.2844298098840193,0.30347736811837694,0.3127437009007161},{0.29980628761665096,0.3123805449207046,0.3059068719708397},{0.2981856218723159,0.3008036738281117,0.3080990580858288},{0.3170427391594282,0.3079737641303931,0.3087611945574856},{0.2967758499142768,0.30979463347643316,0.2927715022249455},{0.30981526897936096,0.3055899461062434,0.31237892651144444},{0.3167174658804802,0.30154787301337893,0.30937395169611226},{0.2901829551251116,0.3015367433550889,0.29686292381491863},{0.29291278813663446,0.29174452827833497,0.3056633326018541},{0.30114987125754783,0.2844280787841655,0.2925193778860437},{0.2947016546262689,0.30381721301652764,0.2870191260987754},{0.2864007454398962,0.29987928542683656,0.2956883174091742},{0.31301810579089245,0.30699207315252974,0.2941478286988063},{0.30233272625494445,0.3073753995726547,0.28714139085234086},{0.29803439854249564,0.29810562167898014,0.30952421576012445},{0.29587069729896537,0.30791706477577757,0.29254630934988374},{0.3083221800719118,0.30068960166811104,0.2842492556447115},{0.31485881423609324,0.2909172760238288,0.322611582301215},{0.3007885523518429,0.29382700742975015,0.30225918703665566},{0.3021903931123238,0.3084768519605659,0.2842038087330879},{0.3163891231818182,0.3194421077177083,0.3014499547749972},{0.2907996931996176,0.30594310806528435,0.31576717676966887},{0.30745766403859764,0.3043318038843026,0.30591590800600266},{0.3112738556895306,0.2987510706632228,0.28150188624716255},{0.3158107341087291,0.3054630291904246,0.3098298007058218},{0.3008010687731245,0.3063327255193647,0.2865479388781006},{0.32291831404766785,0.30407529009828593,0.3107812065681555},{0.2991391283636157,0.2988980419424961,0.30318550827981905},{0.29320896139023156,0.27897301820044823,0.2934411573106935},{0.2987649459034306,0.3007239893464958,0.2976315235275724},{0.30646960925663047,0.3084070095786638,0.29811558952792333},{0.31826524040738335,0.315668334848847,0.29128216008554714},{0.30885311376736396,0.3038041668300242,0.29064224013845946},{0.2984723564448625,0.2808792952395582,0.284696804126756},{0.31643805712634027,0.2867172073932561,0.30271298298811583},{0.3078843053076188,0.29117129133988123,0.2990931940422587},{0.28621966746074884,0.286491138630129,0.2863132291950268},{0.31035836063128347,0.3008262410865341,0.29435824364652613},{0.3076342189651313,0.2932127896069906,0.2835302696617636},{0.31269845633902466,0.29849506838460477,0.3235893649634765},{0.29159280265185555,0.3017121492979505,0.29322955630882},{0.2999658903839635,0.3200430580330361,0.3077998214207624},{0.3057809516253645,0.28862725059248,0.30444223944536447},{0.30165728850375695,0.3077860839277912,0.29240008449593485},{0.2945954562004349,0.3127816823459126,0.2990570478413912},{0.31072214739894194,0.3000469722981632,0.29291922300362805},{0.29806149337810445,0.3011262684077405,0.2888601944671249},{0.2948633899449654,0.30419637860486937,0.31287264536458387},{0.29104438105229724,0.2863212356183219,0.29181781896378445},{0.3166347696725363,0.29512564025696786,0.2984834289858658},{0.29387566482247435,0.3021381285262813,0.3188915682403486},{0.32789090078938626,0.30683229287841185,0.2905013959414534},{0.3026182129299514,0.2968771121482876,0.2974245665781879},{0.297592496998038,0.29075609374746664,0.28609253611470836},{0.2907893000294166,0.29352329114430475,0.2902398276196542},{0.29960622286843835,0.28967044443670914,0.298493324736256},{0.30809758740006554,0.312113082244846,0.29065134402321835},{0.29550701551889214,0.2870172455696256,0.29009153868510645},{0.3038089969292565,0.28794884587635877,0.30566457011275405},{0.31523150507944836,0.3108093137521883,0.3038170044131145},{0.3118574774225349,0.3046540908035179,0.30196317424942626},{0.2916652870378669,0.2918557435412221,0.2921650999966828},{0.30300142943543396,0.3017281436123213,0.30925492832820517},{0.2907488369767055,0.30348558355353505,0.31731632406232985},{0.2858221649612599,0.30727876382955827,0.2814206585324881},{0.28716252107924445,0.2907882714155636,0.29381764698566787},{0.30470357773198575,0.29889237565763344,0.31172728353857665},{0.3025546808168236,0.29521567779594626,0.3139099841984224},{0.3228923172214447,0.29768109136257415,0.30035387664532304},{0.2823386257333398,0.308525122635589,0.30765520370535154},{0.31307705308461325,0.3109740755611706,0.31284845490318214},{0.297358663611122,0.2997697215541711,0.31072764538770203},{0.3048645974162177,0.3120584379689057,0.28601763739627856},{0.28929447583008167,0.30105708700419614,0.29273779518136545},{0.29706131922923645,0.27906342424368286,0.28465005122960446},{0.3099136529199307,0.30049860768897824,0.2951650133940744},{0.28945383250397366,0.28356397511390835,0.29945837704806944},{0.2972511753527464,0.30115469019447105,0.3047143476552275},{0.306732318110102,0.30261529075834737,0.29265704643809604},{0.29775030137869124,0.3007985960594719,0.31808836122208767},{0.2984635948969899,0.30238432754689737,0.3198933045259325},{0.2983798802639579,0.29832939686965027,0.3062213903644825},{0.30774792918893734,0.28353212593886534,0.28683177296562384},{0.3197591635154388,0.3144070088002762,0.3195923766789952},{0.28285532143443015,0.30804885311167085,0.3041627880178153},{0.28219017935148405,0.30747237468628563,0.29945816817996623},{0.30165715786641084,0.291123947294596,0.2837324013504192},{0.2908270285119422,0.30860123102072357,0.29920350238548177},{0.291840714520871,0.2967689600550468,0.2858678612224304},{0.2906714358690901,0.28461442714348856,0.3115277742897476},{0.2881696592024826,0.3078244526676888,0.30799734410336876},{0.29404844877002795,0.30623025271418897,0.2937410671295286},{0.29224782072666006,0.29440820242366733,0.29647076609942347},{0.2868055351491931,0.29754234096236976,0.3096291822812581},{0.29765193471531465,0.29026943193577665,0.3174843569997416},{0.3082312984820256,0.30177467327064855,0.2894087849847908},{0.3107137808576708,0.2863441239478437,0.31928986423652433},{0.2917772149665617,0.2865966526674959,0.3047541358335346},{0.30547687089208353,0.2942489087448771,0.30345461161614856},{0.2981831138963914,0.30126755554244083,0.30320886172524825},{0.2987404462474323,0.29211581779281093,0.3129956865264466},{0.2894835631885558,0.28873967529477923,0.28967228814852614},{0.3178967854140382,0.31342599426633144,0.2986568854074753},{0.32429269078639,0.29935270650340967,0.27679723517896154},{0.30141304067274727,0.2973334743615125,0.3086734511616129},{0.2927334476343122,0.2929466728789756,0.2930506021186038},{0.29126565146290023,0.3063642389870489,0.3047520251510539},{0.2863026288998915,0.29503439427474704,0.3005750195241531},{0.30249244386067303,0.30070334082046396,0.3074504084912686},{0.3075719235456288,0.3142415857973079,0.29733459531232775},{0.3156309784812456,0.2996636864613173,0.2992312395715217},{0.30189520603004094,0.2860321019515945,0.3146347731425853},{0.3161864581210609,0.3107704123862,0.31248318124061686},{0.3010790587273521,0.3119041555065654,0.2979330985384573},{0.28816356936339044,0.3100360086233291,0.31010811519078924},{0.2933410230289896,0.308279807008903,0.297907008110129},{0.3007536011209462,0.3058513518262304,0.28262172275256386},{0.30452933169394975,0.3222340579828358,0.3009960204977682},{0.3206165519697222,0.30518106306276277,0.2971167986683483},{0.2997853633078585,0.29516429259357513,0.3094547020810399},{0.3051084517860248,0.29630631906935506,0.28600892817281515},{0.31096535346338083,0.29277378541548765,0.31142421023162536},{0.2745787499642151,0.3092127755237515,0.2920028857297411},{0.29703836103296594,0.3092120636336621,0.282612790044948},{0.29236411453544275,0.29730703250537277,0.30450988414310887},{0.30224811070337604,0.2969815648791727,0.29569675416639296},{0.3003037327086354,0.3009163644346407,0.3049481604448634},{0.3059858554421275,0.3102085012004559,0.27789540695220694},{0.29666704374034086,0.31072450614308395,0.3025323992185549},{0.3064123531417622,0.29608308238183473,0.3003038133095438},{0.29190515331927464,0.30060196595141964,0.3109193693303499},{0.3073089629457655,0.30475470401210725,0.28896076533158516},{0.31150777569072297,0.2918800774736774,0.30028934503258214},{0.29135397522052214,0.2943540410301819,0.2956634828484479},{0.28339466189230145,0.29167240415535783,0.2845211486382578},{0.31269933535892125,0.298496079913134,0.30385140188738613},{0.3114946253164895,0.292964185554343,0.30516948141266437},{0.2783974959928163,0.300695598291747,0.2936601908049891},{0.3046635997844809,0.3051257999204593,0.28740971663768977},{0.2918893141906758,0.29032257488276725,0.2982616380193368},{0.3093772709006052,0.31967530948754197,0.2855167309365206},{0.2896588492533989,0.28449782597357587,0.3073743741861913},{0.30112988708057853,0.2903168753572979,0.29415936088198924},{0.2880289800562641,0.3119697941714884,0.30423087380450153},{0.3034287377406295,0.3014314314735997,0.2949804177555953},{0.30752936263822045,0.29417205337772234,0.2887373557381604},{0.2903659664720799,0.2920431823483859,0.29147976561175437},{0.2945973639448164,0.31735162936961614,0.30520684066112597},{0.3004869891021558,0.2952066688568085,0.29580616627438794},{0.31016708862443987,0.30061707340635097,0.2985608109732908},{0.29614112839297513,0.2991422405546675,0.2877406420704425},{0.31064524325402115,0.29336538182670974,0.28512520674422104},{0.30871917629662005,0.29887288490988867,0.29098162406189404},{0.29574955194658153,0.28801307987378844,0.2935099559871474},{0.29156329027913597,0.30988926596237604,0.30064825774836623},{0.3028294804030258,0.3145325900925519,0.29875084459177204},{0.3119901918382098,0.3069435061947217,0.2854343176521246},{0.29936534193851677,0.30889344750419123,0.2917314935577731},{0.3067143815318903,0.29355219579054487,0.29226838759765955},{0.3268957660669055,0.3011012495117817,0.3155981706357678}};
                char* data_str = serialize(kirat_data, 480);
                // printf("KIRAT !!!!!! : %s", data_str);
                strcpy((char*)g_secret, data_str);
            } else if (TEST_CONSTANT == 5) {
                int n = 960;
                double kirat_data[n][3] = {{0.30472077237497336,0.29793815303349586,0.29955000794598535},{0.3078301665030787,0.2912209645185217,0.2960653929457446},{0.30182328131658986,0.2973938810952762,0.3012133833098889},{0.2900604374755819,0.31033635858572567,0.2913749127123796},{0.3120344324144312,0.31952994591567385,0.3102703208504343},{0.29650256141477094,0.29798128158934056,0.30425866115024164},{0.2927817513013827,0.28658597839727884,0.3021571089394271},{0.3119928817672088,0.29212441787625437,0.29890005119103613},{0.30387731004662893,0.29498068037632647,0.30343723134773876},{0.3130523321079213,0.30814973627487496,0.30352976029116574},{0.292414517698326,0.30971689737303404,0.31130656970688336},{0.290416687063136,0.2884207824137681,0.2986084567822618},{0.2985745394316117,0.2916594793957321,0.2939565025361392},{0.29894179244715907,0.3115432061430594,0.29723957907709336},{0.3010220138024843,0.30436684726981833,0.29103793582003024},{0.316170988234404,0.3053865420206962,0.3159014571801701},{0.3065520680416001,0.2958122868136489,0.2898398103454945},{0.2982186521688782,0.3073935139841304,0.30123093705530585},{0.2898916144772766,0.3092615543858916,0.3059433090353355},{0.29647753768530094,0.29410768468859766,0.2834643438357566},{0.31181443095634953,0.29762949878274125,0.30086169109497285},{0.29915685496013456,0.3000259964963871,0.2820426542489514},{0.31221561516030316,0.3050365768272654,0.2957263734607259},{0.3038366788580135,0.2925110796825628,0.3086114692101122},{0.29133636135020075,0.30864747814423604,0.30222550400694576},{0.3039949596106282,0.30415376185947235,0.2888727924426531},{0.2886063160398801,0.2893540802070094,0.30310227682849833},{0.31466005409158126,0.30013270539003156,0.2962884221052296},{0.291475226043664,0.28887904087267763,0.30335486427482056},{0.31360771063761855,0.29996552237551083,0.3001647183615875},{0.30420916062226433,0.30650310892811355,0.30579923609293225},{0.31527231214366486,0.29419088199216914,0.31310457286018256},{0.31298157733429255,0.2962082489043893,0.3022049844606716},{0.30475406505806507,0.30135429652119167,0.2953702277518907},{0.3047591747143419,0.29505491165845565,0.29690625703883555},{0.30348681804815103,0.29302314370447374,0.3046633034291506},{0.3015537405070264,0.2988271294074126,0.31971318580235086},{0.3116736947185488,0.3173853698738727,0.3132176294004087},{0.3011326771429752,0.2911405801406259,0.30432065650074575},{0.30165287567706595,0.29687883479039845,0.3036433818261592},{0.30816861931458617,0.2993618510631178,0.30265832690439365},{0.2967167995677809,0.3107469426342593,0.28861040051507236},{0.29683240835688024,0.2983008248154397,0.2791918142401607},{0.2950546340778845,0.29437999074408727,0.31665360005751675},{0.2827483049288399,0.28939496192145064,0.3086945632095583},{0.30191083426322207,0.30604876725771113,0.2988624311797202},{0.29652994265402727,0.30370734259149784,0.30248757661801234},{0.2989346002682669,0.30052880091475176,0.31547853682548077},{0.31367699272455374,0.30037538154537013,0.2957313120730972},{0.29557822829574343,0.2934497735374282,0.29491991816738977},{0.3025803074326123,0.31653585742351686,0.3033740289718678},{0.30433542055198404,0.2982009315591979,0.29289730890770554},{0.29414285500663206,0.3025035941768372,0.29338232069782644},{0.28970111833426165,0.3055490026238283,0.28602029029952464},{0.30197644348963704,0.2913751506750427,0.29981026780578723},{0.2937866683271093,0.30128838605272285,0.2850548485622319},{0.2977888358495552,0.31217316632473036,0.2979873994131477},{0.2944861740268764,0.2915378238374352,0.3075851594830695},{0.30309451540796845,0.310193289896989,0.29339948627935225},{0.3052294561859187,0.2870870622176854,0.2926574434598083},{0.3102997822630666,0.31728158968087783,0.28999562986948185},{0.3038396007496677,0.28326918874867224,0.2920857016693982},{0.3000834678084804,0.29422816611040475,0.3198138689866009},{0.2961525377417009,0.30444688562847033,0.29474031087396885},{0.28978057914387284,0.2912869511798423,0.2897019448676392},{0.3066099471221206,0.3068800976318725,0.30688482265649636},{0.3140351845869145,0.3001540700545543,0.3092091709308532},{0.30463738295898557,0.29201002478767263,0.2903142155633249},{0.3092950847771757,0.2936247585996146,0.2871910433448326},{0.3180265823117624,0.295303432448575,0.2991934232805754},{0.2980274380881687,0.3171205071393575,0.27265261803027396},{0.30329162104982926,0.301434458793069,0.3010179158955251},{0.28345571823167126,0.2934339484596098,0.29408765431945855},{0.2876329985439102,0.3066995215182718,0.31804237046738043},{0.29766129381319784,0.2948902974137552,0.2942340666411602},{0.3014170472049665,0.2939161358653309,0.3014176037082157},{0.3236814770339005,0.3117806224908646,0.3024525974609879},{0.30127366193575467,0.2947030840145274,0.29290027424181725},{0.2976046732686575,0.30200974179559054,0.2910102134649192},{0.3132546228123938,0.2982858457193553,0.2848543499386466},{0.2984876016790457,0.30091292041006024,0.2934090702282051},{0.2968257436794256,0.30389882654005135,0.2686395138639708},{0.2990284355994925,0.3018102315755596,0.29065171495465647},{0.3025265484641549,0.28786271705974115,0.2973815265334421},{0.310751293556953,0.3036761450022169,0.3025795218848716},{0.30635585922208297,0.3089115429708004,0.29579174236639405},{0.2908944354844324,0.29790812515553455,0.2882219087291081},{0.2971630984680285,0.3098549403169066,0.2979374238408372},{0.3117451359527989,0.304808161435281,0.2868402041855751},{0.2872973582628325,0.29002474394049416,0.2892952803503234},{0.29887414072126073,0.2978863118576863,0.3017258375168405},{0.3146196373711239,0.2847521126186844,0.2863779899620616},{0.3057229700995735,0.30060032752581106,0.31295024702971075},{0.2832409974710705,0.30372443148458333,0.30722934671762686},{0.2893570824083349,0.29656117145936756,0.3159924268630253},{0.29756445191503444,0.2993946038215251,0.28783308048541834},{0.30010958626964523,0.2965270681637566,0.3018521010676958},{0.29683768982669434,0.30062983672855453,0.305396422289463},{0.2788052125017319,0.29852168696388554,0.3123448850660109},{0.30187308499412413,0.2904009994449466,0.3055923824529761},{0.3078393735148112,0.30422513150293085,0.2799431154168133},{0.29482424500044013,0.2925019508138075,0.2834412051572913},{0.30513581225049863,0.29848130114088084,0.3060670888498441},{0.3036923166226002,0.2757837687242185,0.3088905397781343},{0.2807531553829672,0.29630876053699623,0.29677489517424377},{0.3067400335558764,0.30393652645173347,0.2851792836563993},{0.28328933352871094,0.2928570311632606,0.28779364776663136},{0.3071849975596765,0.30807542678104244,0.3094259794800189},{0.28209513260678776,0.29677083283438954,0.28949222526312607},{0.2757641215297573,0.30858327755849496,0.3104371645886628},{0.29748617916585035,0.28485154807846547,0.3054164554524221},{0.2988524112168512,0.2840182045071274,0.30838402544685567},{0.31012594612638494,0.28880156326535933,0.30333351615915216},{0.2898766980558944,0.30328237626375504,0.30063568203252117},{0.28126887854331,0.2937529326100739,0.29159734014449645},{0.2993648647347667,0.28355515955306154,0.2833314348092423},{0.30814961731077617,0.3139209755922368,0.2993221882812639},{0.3056292222104585,0.2871245649098749,0.30810410348195555},{0.30489672751631963,0.28796083694443625,0.30079412176101583},{0.31253707323319185,0.3172909120641426,0.3123805801646733},{0.30333121820244524,0.31410144136412094,0.3066388172999087},{0.3104931336046713,0.30391582211468515,0.30711840935046975},{0.3021103131347717,0.29792827620711465,0.2785580583194085},{0.2965074200878156,0.30378178235226505,0.2840488271262932},{0.30568894857959794,0.27380517499087875,0.31944035824599},{0.2935655851233342,0.3153082114348809,0.31364352224570996},{0.27791755450023947,0.2970286504668215,0.30494407944059926},{0.2867741651662273,0.2852429251353093,0.3115561100221725},{0.29097012469434896,0.29657073710030296,0.2863948435354961},{0.3245536392807618,0.30319571933840667,0.3032871090862843},{0.3120227074533625,0.30914860263637167,0.29754457403510065},{0.30166065089762156,0.2987075085652698,0.2955889080272873},{0.2925568516281196,0.3035459872130522,0.303300073300616},{0.30775606958804735,0.2941719747048326,0.2801153216927103},{0.3093854605317352,0.282215354240569,0.29203226681016686},{0.2917080621139223,0.287753778479,0.29567601647488473},{0.2942015303731207,0.3021202238391799,0.30111204433101735},{0.31685556368447665,0.2973893040210438,0.29700224695752137},{0.29125378686845016,0.2860755207525181,0.3043517822956236},{0.28964628851474705,0.30921425318235174,0.2956666316016044},{0.30815207307259546,0.30828013060359233,0.2832293466382457},{0.30973886939182294,0.3081342764987423,0.31696084480546316},{0.3008984522592242,0.3089838306220969,0.3065736126993771},{0.31884310696855694,0.3062369603634358,0.3011180066112608},{0.30264376980011404,0.296173122676919,0.30331160879646496},{0.29571204369984466,0.3089173418549483,0.2856560558387224},{0.2928928199229406,0.29616035597607016,0.2926670159184272},{0.29530001156167496,0.31588064713321046,0.3196976777387767},{0.3067786432756867,0.2894771917835903,0.31043163071715946},{0.28359957803086916,0.30276664201862463,0.30837307510067613},{0.30010866216452237,0.316709146376445,0.31381817070594026},{0.3194602518284773,0.2943422867237927,0.30692015372899273},{0.2917778795194507,0.3044796657453406,0.3034761988755506},{0.2931507992158504,0.29593841353227335,0.3132798259995901},{0.28802046511745505,0.2852378313614908,0.297887610297552},{0.3065137741592999,0.29948628903880203,0.2861484479160308},{0.293886493289844,0.3240553752524896,0.30826626215340736},{0.2922252619601995,0.3180858876061422,0.2783709524209239},{0.29209221655436496,0.30761760779203734,0.29057695238521264},{0.306793630725303,0.29406426075265973,0.3001843067252167},{0.30937231110724955,0.29443800747657334,0.3148507003032235},{0.2971033594396906,0.30973675928765365,0.30641929245004024},{0.2934026368980627,0.29134495336107363,0.3138304582083795},{0.30184488707704266,0.31048562317934614,0.2967600478838008},{0.29210949576773887,0.27583469914629755,0.30282927159695483},{0.2944756628104276,0.28222925967112344,0.29638503862825344},{0.3056041961853813,0.29331316889897396,0.2893196259186189},{0.3211185408002214,0.28642251689796344,0.2886121077565199},{0.2961027498411036,0.29734128092918277,0.2996104449780827},{0.2938740169910117,0.2909608008305564,0.2943011725570618},{0.31136132899961205,0.2968928681424763,0.29766374589133526},{0.29992894854671787,0.29658084938959195,0.28876100651474673},{0.30303572692403014,0.29797842392580787,0.3142557696466093},{0.3080221117411301,0.31138823644233954,0.2962661676973328},{0.2875728027110577,0.3048608260310715,0.30947564449493997},{0.2998779928654295,0.3070945988017117,0.288930794199138},{0.29869684397628876,0.30982226310780475,0.2953904794285882},{0.29043595273035605,0.3137063078504499,0.3106911340223828},{0.2953917397788855,0.3088346327457996,0.30247901085378776},{0.305818185347826,0.29739773474756354,0.30737096306107226},{0.29138594807284485,0.3021340768255593,0.29884478245566815},{0.294570611310423,0.28936956138426806,0.29050375930747735},{0.27669829417740477,0.2940777949080377,0.2978937018386703},{0.30431684677350435,0.30627931501896216,0.3191466989796126},{0.30233657985136775,0.305801022864479,0.288176144195166},{0.2922677755555566,0.2888004530367937,0.29473190522111725},{0.3016510620692283,0.30322139017588157,0.3072348664595018},{0.29626409887085486,0.31300267629241485,0.2823204926488268},{0.30503255962443016,0.2855701046630108,0.2869822870849061},{0.2997503018597674,0.30934805914236435,0.2955564487196308},{0.30132588561454,0.30034805119565183,0.28890800054649796},{0.2955357101846041,0.29389945456553435,0.3125706114604246},{0.3016454558938251,0.28995853455186515,0.3165141854678279},{0.29480109306681296,0.30286767516041074,0.2940531921774929},{0.3055336016638236,0.2750249813981782,0.29242751457508925},{0.3022088134594991,0.2997120331103644,0.3082348241890285},{0.2926537401250297,0.28545243214387744,0.2968055802887613},{0.2965741209749825,0.29467514556778074,0.3117790306976421},{0.3025847095940902,0.31267613759825896,0.3024894918215008},{0.3001728446920473,0.29782561869962965,0.3094092046820895},{0.2953428464928629,0.2990825657546018,0.3089526728714809},{0.30544226923779844,0.2845582940787651,0.31208943512226983},{0.29703037116355,0.30704993706962114,0.29148594834883196},{0.31050188645427196,0.311386589749324,0.30374964533627336},{0.30923890170964524,0.30225721048804705,0.31196363992992376},{0.3042571779333136,0.2935259270743384,0.30367824664121273},{0.31144738548000056,0.2998517302745616,0.2911399336976266},{0.3022231637000046,0.30719648654028714,0.313151452954285},{0.2839158201821979,0.3013989927060375,0.2822758358800267},{0.31430670577141756,0.2938017614627371,0.2903703305918768},{0.2826373439250508,0.283526988344345,0.3144269652378346},{0.3016066935728515,0.3056467136651386,0.29730429461577174},{0.30959114503155866,0.3112140996603155,0.2737489913266995},{0.304847867939446,0.31801895730674945,0.3131749698831631},{0.30776063934884335,0.30288428593197425,0.29102687023305507},{0.2878454822908257,0.3075248202592253,0.2922528751650463},{0.3135266937592879,0.3187999612850829,0.28632585865249066},{0.2968502872591742,0.28593767251147206,0.2990798470507114},{0.293707023331586,0.30431063923758667,0.2980932632532298},{0.30580327608266944,0.2808025516746088,0.30698766219734974},{0.30372607873203555,0.31309374241362026,0.29224123327842305},{0.2950537386626334,0.30756464104688436,0.29412975428390076},{0.3089246482714422,0.2980928395436346,0.3177492771163675},{0.3016946160341624,0.29505703032019487,0.3066064886722645},{0.3136260143302925,0.28868886831099655,0.2970818426517694},{0.2973915177396309,0.29715625548164526,0.2857734917589055},{0.29275883576745476,0.2965661082234779,0.311798671753066},{0.3076123628648736,0.30792048313682785,0.2919600434667474},{0.30399500173651484,0.29034092395189126,0.30443519441455213},{0.2835172080064884,0.3069469796421728,0.2918720762946434},{0.3068054847691305,0.30908905450078716,0.3009855506806551},{0.3073282246309398,0.3066670432289127,0.3189016150089279},{0.2956334505124253,0.30562650803493796,0.3049816866838604},{0.3223544776529071,0.3086456696634016,0.2831306870347633},{0.3255575489705239,0.29420407706643575,0.300047199854294},{0.3015114134820561,0.29641494650945666,0.2947731741301806},{0.3167557047677147,0.31338101747324904,0.3161622463249552},{0.2955436731170081,0.298913571937066,0.29775541057025384},{0.311569489271115,0.2800220060067481,0.2947808047711927},{0.29781349544375857,0.31324227517476133,0.3134249779835703},{0.31957679269750333,0.2936025723485117,0.2964736450702409},{0.28795791942653054,0.29978109012400767,0.29745928672378796},{0.26757156177291097,0.310383949603252,0.2918001748625902},{0.30109936932483494,0.30243982659076124,0.317926873368394},{0.30160141435873306,0.2969994821301124,0.3121461657189816},{0.30131330848212534,0.2911855488210359,0.30417423178328834},{0.288801040450594,0.2966771612972376,0.2796048644764247},{0.29793465095823807,0.30186528308769284,0.3117490213653797},{0.28901915955566887,0.3053354849363107,0.3048506394454557},{0.3003491586047812,0.3083898107666281,0.2869986780618819},{0.31052376069419757,0.2974114452073555,0.2878541011444727},{0.31247921122409983,0.29510705250905367,0.29828815091126404},{0.314744105732481,0.2905627576334467,0.2994836007969309},{0.2859117887141058,0.2843159585212079,0.30038624407302844},{0.3027690133855391,0.3000645330485925,0.3044620421029134},{0.29768961311743014,0.2955007415187737,0.29244569733206244},{0.2988923112202574,0.2941358180040925,0.30553442725451696},{0.3120345613535996,0.2886478633359364,0.28219876712949893},{0.3062138721417449,0.3147929646175137,0.284368242372094},{0.31228991460203065,0.2931423159794937,0.2895516166446318},{0.2900959259160245,0.30322307655216746,0.3002717914100347},{0.3036735947765702,0.3018105628831834,0.2890152374007233},{0.292842619707343,0.2950927512892704,0.2999653843913542},{0.30812434709287045,0.31606740668603794,0.30539305936639555},{0.28809870877356525,0.3043325035568748,0.311331572608103},{0.2900030721419012,0.31407051829451693,0.2940775007065932},{0.29490293675910384,0.30393133399270955,0.28513710974724576},{0.28661719554290815,0.2975860248733909,0.291900751200535},{0.3015718064992795,0.3104325986875863,0.3014278650039715},{0.2857717275597993,0.30033535993930793,0.31146655620477764},{0.3011840904371387,0.2955909336797149,0.30016822141393895},{0.30698686165867434,0.2842976514920247,0.31507910625692326},{0.2984440334226135,0.3019571762703291,0.3102997402335096},{0.2977904862859092,0.313018323033369,0.2963297962903429},{0.3155689062882524,0.2954813312891083,0.29903750095278203},{0.30514758723471397,0.3051487714508232,0.30709906357839234},{0.30122401819100914,0.2828586290077355,0.2875983060041373},{0.2853878407495221,0.2816479391431084,0.2768135358129849},{0.29522477951894244,0.2997489989458236,0.30285745443470047},{0.30344305673919325,0.3031103472884485,0.31242049277989364},{0.2892594336158622,0.29161399618204076,0.29223560808983273},{0.2922666983110862,0.3149666825709701,0.3137630123768161},{0.3011901518070546,0.2943415974452957,0.30694543024182736},{0.2791710057565071,0.3011620844918732,0.30614832170816186},{0.31873919226076186,0.3028642862239969,0.31328117161101354},{0.295307444794732,0.2865053133666985,0.3050642678717699},{0.28984718751982774,0.30382281204228934,0.3062204440309227},{0.30333293846152626,0.2911320834053472,0.3018582992866322},{0.29221290858579646,0.3059636696934903,0.29780724416768717},{0.30117016305623734,0.297127580543456,0.2800070469228986},{0.30840893100346695,0.29000057071101,0.32375887600960196},{0.3041017795126373,0.293650512708673,0.3102961216811695},{0.29976603706745675,0.29382250813628213,0.3070215894173565},{0.28582141408885625,0.3179300685178688,0.29910238462267136},{0.30671709729181657,0.30376926478534877,0.30536568685679677},{0.30557026165967877,0.3020512736033827,0.297065926411103},{0.290374878696824,0.28689641793184034,0.32130797696057595},{0.2831152745758365,0.3018846206846223,0.3019529051862716},{0.3014979878897122,0.29773678457938635,0.2887016769347615},{0.30278673097847925,0.3044712616301719,0.306835515058482},{0.2992291958836753,0.2927814295181318,0.3071587939673987},{0.2825894929031813,0.28966502218389123,0.3123327752225486},{0.2846702134399111,0.3090369327233835,0.3043904898923325},{0.29039558175414687,0.2957565505501384,0.30758174143444167},{0.3109275009982075,0.2943220987190243,0.2999613609545066},{0.3047111207225983,0.30020414790062483,0.30625383271064754},{0.2939926986321454,0.3009691183361301,0.3029813444167201},{0.3012057148980189,0.3086779821976799,0.28712117438382617},{0.28542451698088983,0.29475040935100166,0.33384795661033606},{0.29749379322198893,0.28503135203805385,0.30325734970407375},{0.29976125843675666,0.3069329172998008,0.3058915674380213},{0.31768980352650583,0.302781675338404,0.30433749666013726},{0.30362389894203384,0.29887901002400635,0.29133154034947145},{0.2986061685213321,0.297595766189002,0.3105086713477348},{0.3016333601319532,0.3015646320354345,0.30059731992967176},{0.2752291530330812,0.30855366314074084,0.29683152420327097},{0.31962866745364127,0.3005831934964225,0.3081420657677069},{0.30810745396639744,0.3135778216060488,0.2946746851139262},{0.27265828335710257,0.2922035426951259,0.3038992347702853},{0.2791278187989642,0.30308637804259364,0.29104078481502205},{0.2928822522323677,0.30792735832400586,0.2879799866537211},{0.3091243210857997,0.319318969448696,0.31380071296529954},{0.2911782624479649,0.3200995954739517,0.30288394385157996},{0.29578173055569895,0.29560047584918375,0.30741742763542546},{0.29313950579770626,0.31185004195190585,0.30496247908655827},{0.3235445618814237,0.29272924062742517,0.28180874520210597},{0.2953285624692633,0.2954011611466965,0.2932781304330949},{0.3035933474740585,0.3031095833499238,0.301487291269707},{0.30546760608649953,0.2887963906679722,0.306255536243516},{0.29740902341674363,0.31337149646324364,0.30324040697227755},{0.288620590511894,0.3017565124452552,0.296797401387135},{0.30359445971809945,0.28209939918792276,0.3034491726116165},{0.2911216236504575,0.29971702670513634,0.2870406289634006},{0.28560037572683583,0.3102747928380568,0.29759170752832115},{0.314469683698668,0.29938688133202473,0.2882554384985441},{0.301523604244509,0.3120930780767205,0.3112902448110061},{0.2998589290538181,0.31011753818155874,0.2890522100257064},{0.2942010705397095,0.2974915965717266,0.30060982386642715},{0.2948349010285724,0.29520471698804157,0.29107808824886455},{0.31351151829071094,0.31242304028024087,0.3031393764853549},{0.2879111275525347,0.30293060240305786,0.31502623879536},{0.28819907673180073,0.29297076151731766,0.2843297098125753},{0.2908613519501188,0.310071178331619,0.2859772769994247},{0.3088825442642055,0.29991407309408613,0.31292007352249607},{0.2859011452156607,0.3044162431809077,0.30125145309673823},{0.2998224960597604,0.2888787695719065,0.2882131210115499},{0.30997261513537716,0.2878175645435808,0.30900247267707925},{0.281835996616142,0.3039890515206365,0.2894329818038334},{0.28549035505947884,0.303884259038272,0.314284411036894},{0.31297553910079956,0.2931781704933326,0.2895154772674686},{0.2941463171747288,0.2975417959203294,0.2947212672112294},{0.31084276066830047,0.31681293588108367,0.3094677536850781},{0.28698227330437087,0.29140898062167003,0.31523954488234623},{0.29877677080695286,0.30807761649497983,0.3140530927627392},{0.3108562357014084,0.2880876450292331,0.3099052218678306},{0.3004967137047887,0.3043567266716878,0.2896580982274074},{0.29357093463347217,0.2989579117300981,0.3088154164241607},{0.27975676377553055,0.2850518215399763,0.2986175246329536},{0.28757417388387596,0.28900706264640197,0.29766215047031785},{0.2999069841347975,0.3043575848613711,0.3029552053000245},{0.31362525496518784,0.3045518523458117,0.3048831986334321},{0.3071910048265635,0.2942608276670418,0.2919725951436205},{0.28842365965656047,0.2954317938385348,0.28503271112578205},{0.31108691207561545,0.2931970253797967,0.3019076253298616},{0.3081881943473252,0.29708435201450106,0.3066842029474524},{0.31220408758435053,0.29184610583025533,0.3057211186407449},{0.300021775331732,0.29787686035081856,0.2916184146270502},{0.299231346250361,0.29412756164272313,0.29352208595554724},{0.30702063470207164,0.28785733627823085,0.3029269275629538},{0.2978877627319898,0.313925949864503,0.2925721296361954},{0.29221001780580524,0.2767830077428179,0.30802220521072204},{0.2894106045171405,0.2932702756165172,0.2865616897615576},{0.30088494756824247,0.28857609564256775,0.30591393558943897},{0.3000185610156546,0.30195377749444363,0.29321524879521715},{0.3174642774143932,0.29826559942440267,0.32090913880792793},{0.2983418193454507,0.32180526004457427,0.2788274106620207},{0.293023051551823,0.31822091862875995,0.2924089855271676},{0.2985323521986517,0.3086740260800026,0.305966115034794},{0.30203254940219676,0.29047068122633524,0.28959690864114984},{0.2873209312748811,0.29676426957598956,0.2758065970449718},{0.3093510195864087,0.3016599399993731,0.3045178455016762},{0.29683303643656705,0.2980851639376912,0.30689699184763225},{0.3186877152564322,0.31741576653635306,0.30510547823028605},{0.2936114632264907,0.3097831139033889,0.2853936972015355},{0.29387824592449646,0.29425792698216013,0.29798763348736024},{0.30678484051095917,0.30373984484165645,0.28694793084164777},{0.29955556311625625,0.316194981674807,0.28762952733661956},{0.3044054302168572,0.2858150275621258,0.3040406485348443},{0.3038052800810544,0.3087610822400414,0.2995524318147397},{0.29707669855650687,0.2905435766624861,0.2925364232143528},{0.29284846353767363,0.29456136948026,0.30101206782843054},{0.30700940652214603,0.3149249656363756,0.29852528011624535},{0.30661880035528094,0.31673249653844626,0.2985528760858551},{0.2827307262199097,0.29895100970102056,0.3181799207104355},{0.28977696980941514,0.3110260091363731,0.30994781515665576},{0.29950900345711445,0.29831964542567524,0.31303424315401385},{0.29638233956663534,0.29703437290381346,0.2938779636128404},{0.292120203276966,0.28646744116902517,0.3010184595555229},{0.29474554526427044,0.32014545377988424,0.2991042921497411},{0.2988705188658901,0.28755601600408365,0.2992558087878108},{0.30629753008230376,0.29559644513354366,0.28695720853336637},{0.30316532063182844,0.30272924293970677,0.29013314231258863},{0.2926156930822185,0.27715345360567595,0.3075468546084841},{0.3122032021053681,0.30654776462425093,0.29961623534596227},{0.3170428874274721,0.2862008161748471,0.293860002131178},{0.2916565010033736,0.2881191371676769,0.30246907629091585},{0.30073387333370794,0.3083897851964106,0.3146185045217381},{0.3000075503833467,0.28330496540987726,0.3051597163439763},{0.31261207262819013,0.29297891563579453,0.2885937472665976},{0.3158777612256037,0.29977682872170874,0.3247603729277848},{0.3007834470917808,0.3151430018013463,0.29154032601229307},{0.29491998209026155,0.28293595833913865,0.3049345626620244},{0.2920887694682319,0.31236579774100454,0.3101595743165335},{0.30285792882853313,0.3019100833268006,0.2958755858283528},{0.3059701170992802,0.29984227582618483,0.3074226631516193},{0.29701164046967404,0.27181547526851674,0.29541447168593754},{0.28112701022346065,0.3042049316857199,0.2982562547450831},{0.2900550682629109,0.29725226258382703,0.2791701787326752},{0.28738522895886115,0.3115074248339232,0.2983112858407724},{0.30081035940894074,0.2869978502040571,0.2809304150402461},{0.30211214147468474,0.3062979997400336,0.298875682031145},{0.32170569801665283,0.29333591658773595,0.31657116804979046},{0.2997800198087479,0.2972948789605991,0.2986643742341454},{0.29353822128449747,0.30856912998223013,0.28633027773317515},{0.2971403685139176,0.30929358416213387,0.3084261100943743},{0.29849637889361424,0.2975632598348722,0.29923950012755957},{0.3171752175098885,0.30296702926083835,0.28910064775575},{0.2915999299140225,0.2813379775819152,0.2905701981412849},{0.2826919495332853,0.30418919566911573,0.2957536870392701},{0.2897693123125705,0.29554696967411315,0.3067065891949979},{0.28969877752240947,0.3271022980641536,0.302708678840423},{0.30493497019623794,0.30106139087983186,0.31482129396326597},{0.2896180759191326,0.2849645923837466,0.30825292384249525},{0.32258473325246767,0.3016924383324564,0.2931272695615082},{0.285588741312526,0.3056046963904119,0.31045123304906375},{0.2833423791018708,0.2859995497145059,0.29784406202851954},{0.2967965313891316,0.3130314649537991,0.30280879917128145},{0.30794256521622065,0.3109834101994885,0.2932600160980755},{0.30400002177566593,0.2969154261838585,0.29278307469547765},{0.31187027670769357,0.3063621841303001,0.3109468461911127},{0.29890668752528404,0.2980076234200054,0.30131940872017926},{0.31341244695323456,0.3091603806351843,0.305905191678248},{0.31183444779016833,0.30371373525681117,0.3022316652012177},{0.3035301618354739,0.29430193468550997,0.30993907656998787},{0.30030442993600703,0.3182262807176736,0.2907456684534118},{0.3002416806753266,0.31328608405151737,0.3039044735632718},{0.29989155933012845,0.30160302120732135,0.28798574829676654},{0.28194748102582456,0.2844698797579702,0.2927131100683437},{0.293012158208629,0.2746503071616961,0.2985192130484838},{0.306997155842099,0.3014574257153358,0.2976390723765758},{0.30624837829545726,0.2968245985865338,0.289418666125643},{0.2994720086726323,0.30179084411920515,0.29235627639729705},{0.3030974442688315,0.2904791856804105,0.31413195515703624},{0.28330833151729057,0.3039759810510561,0.2994145802123283},{0.28103091782964573,0.306610125793606,0.30437173931204},{0.29374974658392705,0.29564867369229697,0.29139631325249143},{0.29547892453963165,0.3099752744637417,0.2662017379701495},{0.30126354144704454,0.28944040259932485,0.2930264194208458},{0.29698517178036393,0.3001581978458906,0.29499790417541616},{0.2949744233403157,0.3112646274119794,0.29513911216625194},{0.2868392735322796,0.3137132956348215,0.30475220423463967},{0.3116157614162244,0.281562540841516,0.3019423710302941},{0.29761458104552563,0.31640100652436826,0.29834030812495504},{0.29305505397298365,0.2906438709226368,0.2993054942555405},{0.30077520993405155,0.2891667630742417,0.29858178731611845},{0.292126478383002,0.30600186462756546,0.29827391924862157},{0.28866741543771746,0.30161034973086676,0.3023688472621996},{0.2969141023660772,0.2967609148847526,0.2949720085085543},{0.3054977268868194,0.30010066762304155,0.3070942871792079},{0.30724510665583693,0.32252841388952624,0.3073124463254638},{0.3102883548370801,0.3013534491051357,0.30814723187759885},{0.2935568231839011,0.2892062884606907,0.3151831363259483},{0.28519352070970644,0.28630685189174915,0.3109102268149661},{0.3039821322079055,0.2989047399978754,0.30335001692172714},{0.29543540105924265,0.3243814151597767,0.3061525643705492},{0.287230778917217,0.28447728998110444,0.3147766458185709},{0.31738121320615004,0.30159221136512276,0.2894199730069203},{0.3031302177126166,0.3071760765881131,0.30279676588773646},{0.29986976639578056,0.30030336274049235,0.2995906167578549},{0.31320769060175946,0.285611840241816,0.2960980180530663},{0.2819603294578304,0.27670873545032115,0.3001943082299426},{0.2934947924948356,0.29373034602098763,0.29865381554393644},{0.2992918399312724,0.30200208881431306,0.3011216522282455},{0.31828350546212714,0.3110630562840049,0.3085301154716832},{0.29967225546168275,0.2938041312620369,0.2814462529910668},{0.30739826277913374,0.30624200023905207,0.2890676347688986},{0.3086731246261611,0.3185269702379887,0.3064807974773313},{0.2997314532595591,0.30706981651501614,0.30925149798826},{0.2998253394844909,0.30835345130892355,0.31143324457965554},{0.2940274848331075,0.287082894091244,0.2950750865230613},{0.3106743788994821,0.31408202914684824,0.30298799561068607},{0.3078822041673858,0.29162659164121757,0.3185653929019568},{0.3009446181238417,0.2953144688384741,0.3220179913441965},{0.2899756821649484,0.29390734777269256,0.2857943736235293},{0.3201604683102148,0.2965054108243448,0.3113781188156424},{0.2801626221717352,0.3007251919027959,0.2914167846188245},{0.3078896295335873,0.30212006628862137,0.292915733685047},{0.29930031339075824,0.3085637625989502,0.32205090090583516},{0.3056665926754179,0.3012775774650057,0.2937375671317832},{0.30698477444812955,0.30553074820375065,0.31152916855347623},{0.30066011378271695,0.2938358091804132,0.2911806475723107},{0.29372911589997963,0.2990263863157663,0.3061860960057451},{0.30856846472807387,0.30054318860851487,0.2980742077089809},{0.2967432245861735,0.31296140499628483,0.3066352180758155},{0.2913262101044771,0.3014297954876869,0.29419227007526016},{0.3088418311860015,0.3019874044393187,0.2927217878756722},{0.29644681419711216,0.2956437886296143,0.3164446689406028},{0.3060256047121051,0.30429140967164786,0.2971415136681106},{0.2918929407614948,0.29602923943789156,0.3013164099662218},{0.3079635339429176,0.29917578449143784,0.2777605857961121},{0.291895077772182,0.31350894528888046,0.28217626751930136},{0.29754377134481413,0.3269553238345404,0.2957467637048482},{0.30452433513301275,0.2944947732054527,0.2980851857129023},{0.2865828840009151,0.305106663342382,0.3120594911549364},{0.3015799834164161,0.31453830054894033,0.2834572584153538},{0.30256843452566,0.2953848251963323,0.30630988799408804},{0.2952965531839869,0.2860159515612163,0.2950779416376837},{0.282939317362061,0.2923635206523961,0.29288405147590457},{0.29858781086781966,0.31331500186841305,0.30673477804823374},{0.3081099928092915,0.30811032534754756,0.286567363433021},{0.2975906027566263,0.28189408402399807,0.31135561214132623},{0.302409552701473,0.29257025014474797,0.2705693894871968},{0.3005476856465974,0.3108051574576981,0.28210795764384705},{0.29387140748068424,0.3028342398770071,0.31418468427479107},{0.293999870665793,0.31266504538504086,0.318675731412452},{0.3024141058132155,0.29341770703240316,0.2919106937850135},{0.2929724214655798,0.2816583209740621,0.29695184064462016},{0.3038671100480686,0.31338666437875395,0.30225868546887386},{0.31589022225247554,0.30229449228023364,0.3028926548048375},{0.2745103838348858,0.3232267057851475,0.31389245794035153},{0.3080897535250408,0.3128700326967566,0.3048947500748853},{0.2962174007073622,0.31337985865317297,0.3125982507950101},{0.3055761305036697,0.3077985703418005,0.286255182142702},{0.2979302018944374,0.28697154550210824,0.2883063641213336},{0.2988251715313472,0.29281519898696257,0.30894121671249974},{0.2969350379691099,0.30537954148887225,0.29671019015696465},{0.27656943897682523,0.2983841893937927,0.3023139857368081},{0.30278786433482663,0.3080318078281967,0.28864883949586256},{0.28410794603744166,0.30316039088919394,0.2900094408593754},{0.30622877500611495,0.298044177432681,0.28743011741737756},{0.2784265616806861,0.3008308200656567,0.30711858398851},{0.31030367626793837,0.30910465523836494,0.2866041920273911},{0.3024071693014865,0.3054212955480124,0.2919592092952551},{0.31292034270154395,0.31386186663430365,0.3057142030726347},{0.3110062776306401,0.3022386942830283,0.30895635706686103},{0.299100970258189,0.2901921749210816,0.28928331798913315},{0.31411894621760034,0.30670853443852797,0.3057133351739632},{0.3194389559901696,0.3220078578094636,0.3002122338322226},{0.3028744422574245,0.29742173745693185,0.3036729536722647},{0.3006151535011788,0.28903266311803993,0.2998506026714763},{0.29284284817985784,0.29563954599628284,0.29981551247419685},{0.3146334558256209,0.3111249170690821,0.2901748034952677},{0.3035607621886472,0.2861257473216019,0.27729772352245097},{0.30979150828012864,0.30440998309297645,0.2922215173568543},{0.29125365020463684,0.29035703878335667,0.2888642016858207},{0.3100621072533045,0.2913855328368361,0.2934416726121613},{0.2885433749688298,0.29062712897205645,0.3132763174149886},{0.31035924195658904,0.3033367870319646,0.30507810012569997},{0.28073167509787217,0.31704687416179883,0.31015889732804647},{0.3005205865489474,0.2928082971259213,0.3020113966407969},{0.31685441357974325,0.27575215475672565,0.3026152031971303},{0.28707846642834967,0.301988479599897,0.30349356715735615},{0.2820315550052791,0.30141550455247346,0.3118643091439358},{0.3025991863903012,0.29568771051416487,0.3182260164327151},{0.28564729760903645,0.296019524727697,0.30940013010567136},{0.29029957818167795,0.3135642661125698,0.2996610930146364},{0.2855111749009156,0.30388643607665605,0.302583504229565},{0.2968324373459612,0.30974156210790815,0.2972647905089004},{0.2923120248783621,0.30242166043674207,0.3005790802321483},{0.3024644103660343,0.28553110020538525,0.2914811253445943},{0.2926764033494254,0.31241858226840313,0.31075528248296214},{0.30426033639500627,0.3165001517113578,0.28997529042751324},{0.3078268546387602,0.3110974420006355,0.30810451587279597},{0.306325271238344,0.28870754599899445,0.3199718692791722},{0.2835903666632773,0.3157021577663243,0.28704634820299807},{0.29410119636697934,0.2979113439079005,0.3196423720068186},{0.3025020613965876,0.3065937257386516,0.3003520491973239},{0.3036102600783406,0.2978085006042816,0.3111288716540416},{0.299846488286978,0.2702875830620511,0.2974573351670706},{0.2974110948020746,0.313105286638045,0.2880846154312025},{0.3052648382960364,0.30372561309428314,0.30156021602704136},{0.29970640039385593,0.29597818902542394,0.2920637969265925},{0.2979770143548887,0.30753369702018146,0.2966683565832583},{0.28490471616727814,0.3083736185240302,0.3186949042567958},{0.2841947681107343,0.28134877082027815,0.30945756025092863},{0.30523013689586187,0.3025147042587099,0.30896289433439444},{0.2995606181819225,0.2879755909493151,0.28936176351110876},{0.30395171298767854,0.29505792540524434,0.29910080986597076},{0.2907894867454075,0.3063431341205735,0.30993878148253223},{0.29773866115554787,0.30427181520505525,0.2982524171266584},{0.3000844316021535,0.30953969090941374,0.29944937260364707},{0.3112175557183332,0.28969435073560507,0.2964225629222873},{0.3153526689075727,0.30925635041096017,0.2976392873041181},{0.2946887333296181,0.3112347840854656,0.3013686385587538},{0.2983363387736282,0.32331985170753724,0.30599458468016655},{0.29001210996610594,0.2991153937912237,0.2813993970525603},{0.3090929053658201,0.2999668283976581,0.30296030655133793},{0.295080947151935,0.3135227081230653,0.3152685149618129},{0.3046265625002689,0.30196582417773965,0.2889430545593246},{0.2845924826375057,0.31326307548171944,0.28895180677907434},{0.3046218821137706,0.2905848221839392,0.2920970729146403},{0.3045900527743401,0.303070381364427,0.29430789684699193},{0.29596726599915696,0.29631835538347107,0.30201844647071396},{0.2906354152402644,0.3061863526001179,0.29744269510064797},{0.30341659590967585,0.3106342998401485,0.30365568026833956},{0.28897577297576976,0.3016419744244128,0.30034448656500745},{0.3013407201440237,0.30137528201680863,0.29517084274584227},{0.3014881459623872,0.2995334131243511,0.30139594611464976},{0.30318052126658335,0.28494311677945067,0.2933653547601746},{0.2889565963350697,0.3123230710683027,0.2998392420780103},{0.2984786907424567,0.30431499802359646,0.2931967727861888},{0.3105927460183318,0.30315713746633666,0.296542339340135},{0.2785813674171019,0.3027794878834242,0.3037530308387497},{0.3023145112304622,0.3103804770082764,0.3134768026275455},{0.316024657776652,0.2957099566197142,0.30837821917816327},{0.28380880003439224,0.2957777881297089,0.3041891460587513},{0.3113118958368219,0.291030383475527,0.3086195002685934},{0.3091777336221973,0.2984413477614475,0.3144978755245556},{0.28698251393259394,0.30094775219347136,0.2947810972746615},{0.29474890791225306,0.31022311909573674,0.3110875028891627},{0.2997040650624826,0.3000576927265106,0.3002731676461285},{0.3068668286716061,0.2825923781471428,0.2876723169320567},{0.29716561645808337,0.3011480478929889,0.29333226969464765},{0.297710264191203,0.3037080503652454,0.29913329039916897},{0.2961156008735423,0.29775467234147945,0.2974836598046882},{0.30962356470593,0.29768506116474347,0.303476780055776},{0.3052635273635196,0.30807648049726566,0.28832903413629396},{0.2899725391719259,0.29079251967897907,0.28216402353087644},{0.3048916834594773,0.3152179771534021,0.3018440277605452},{0.3071085904824827,0.3011165121119271,0.2951615425725052},{0.304044767244186,0.2976295320489295,0.300490762863509},{0.2869011806273895,0.30072854416058264,0.30531801255383584},{0.30152432313792255,0.3084109781927121,0.30830578078084603},{0.28187753055012854,0.30305096069890464,0.30762614197250976},{0.2818211855370339,0.31183561903464335,0.30102485472053325},{0.2940653458096488,0.28945857957733245,0.3145774856873619},{0.30397085131177803,0.3028124695444211,0.3110022643385612},{0.32131147684980843,0.3236211422852124,0.2962909751732551},{0.3096072147982902,0.3062807725597556,0.29610631525998304},{0.28217708663741087,0.29848126963217875,0.30785577713216067},{0.30651072244230665,0.3085593141693189,0.2862313496187393},{0.30054072520035796,0.2864654099587089,0.30465464290579},{0.28597057168242307,0.29487868985825205,0.2815376444182433},{0.3073107750162784,0.3009888099921101,0.29638248865803757},{0.2982254102811018,0.31605386669773405,0.30145635869952275},{0.2982705676413112,0.291892360186449,0.2928329385601137},{0.30149829640055115,0.29868232171714604,0.2907994786115766},{0.2875626634137778,0.2985245193850012,0.2827643623413485},{0.2976246360452623,0.29254239499115675,0.3079466450786409},{0.30054695786524566,0.2991222400319322,0.3146636864480971},{0.3127789619528045,0.31692057263354667,0.29173279480867176},{0.30884590643388726,0.2915649103928207,0.2977683048146409},{0.2992924702405315,0.3007815733503407,0.3009907404491053},{0.3102972302380204,0.31021630497493746,0.3005380998260304},{0.30382803359816507,0.30024172721813014,0.29286335323817103},{0.3036891267477589,0.3018710270658515,0.3104825340138177},{0.28813074901157465,0.31567658297926293,0.315413786778915},{0.30941368595656865,0.28744976466846867,0.30884593912545505},{0.31950104077259467,0.31668588176237844,0.30389410354777324},{0.29411556555383467,0.2878123779775042,0.30110631046970987},{0.3204422542608887,0.30083043815043514,0.30166446452139156},{0.30605141345088116,0.31242719951622133,0.2953765164162851},{0.3145913635368075,0.3065480337125134,0.2830603243799741},{0.30270029330039555,0.30724283444351286,0.2847677371999625},{0.29173854052239656,0.2949892227345139,0.28404134376594486},{0.3103721366123279,0.30830490360950386,0.2805497695127109},{0.30353551326421746,0.2943564046986516,0.2991186734523923},{0.29333158086396255,0.3060445204997359,0.3137536530042762},{0.29588764853774435,0.30508961776114774,0.30865496497459005},{0.3085468117503019,0.32375715575322755,0.30842896874414577},{0.2937012224083875,0.2989537911532559,0.3154992584817049},{0.2996957451392577,0.3045997296963332,0.28434179231402784},{0.2934185521727472,0.3125660308492955,0.29398099849807063},{0.31155966201344715,0.294251603899649,0.30116983303093914},{0.31629698538045714,0.3177017873350381,0.2821548436978431},{0.2999156496495502,0.3130553412457451,0.308075413157882},{0.2993746513473421,0.30000721469184305,0.3205932115711793},{0.2987776551336861,0.3004516656443163,0.3090978176625715},{0.2996977882768283,0.30579515180377276,0.2944808026965456},{0.28662240338524303,0.29232367877019594,0.3035160545135304},{0.30537736385221376,0.3033596073992399,0.3247102494690733},{0.30795429360721843,0.29549606986632887,0.3041055519288143},{0.3022470813087874,0.2936053170154353,0.3146712599298449},{0.2909593367341144,0.28395341291885556,0.30810970747079885},{0.29888769709543134,0.2927951952489117,0.2859492595887214},{0.2902545484997986,0.30529404511204156,0.288756805655628},{0.3014891149532535,0.27451411646593527,0.2951463488374145},{0.28644695090247396,0.3273874482969281,0.2995043135155185},{0.28818077054799573,0.2975622210205913,0.30507440443995487},{0.31384049078173837,0.29530068467552834,0.3055656676998074},{0.3055250161201892,0.314326874899782,0.29015074157116016},{0.30672933071711717,0.3123158969685916,0.30500708690146466},{0.31394347752570323,0.3104119809461535,0.28829858319018103},{0.28343563998796617,0.28315802889613695,0.2990674771242596},{0.31271487357867556,0.30133598229622305,0.3068948351507032},{0.31842917156887257,0.3084303484056163,0.29525497639440057},{0.2813139451544389,0.3006289894874739,0.29567772347955473},{0.2971268839511554,0.2896268488549367,0.2991093851370711},{0.2994665037069205,0.2938968380254378,0.2892586182415672},{0.2902042272222226,0.29918735335615926,0.29442896464279644},{0.30306871091199916,0.2995413556173866,0.29374283130119044},{0.2936213978180499,0.28686261259839235,0.3102067468648158},{0.3052341792527001,0.3041530036080945,0.3015033580200458},{0.3001409581133045,0.30888147388765824,0.30755762602587494},{0.2814842241766352,0.29021709862586736,0.3035369690806335},{0.3003887042880042,0.28688631168547046,0.29887751782924393},{0.2936252475284578,0.30226129856697187,0.2897234119501625},{0.2960472271801511,0.2945782647472635,0.2868155924299227},{0.2967518769061189,0.29968831825190057,0.2992055151470286},{0.3031715002945061,0.3080309502963287,0.2897019817513458},{0.2990930671966578,0.30476628616118406,0.30064401530025386},{0.2900072833241499,0.2931534637956047,0.30443366742949124},{0.29594763779203864,0.2830214423760769,0.2857259315311842},{0.2808418817491953,0.28757641481233803,0.30629370728746563},{0.29240423504546476,0.31508462540996174,0.299149411552543},{0.29444180445135915,0.2919218562404331,0.3004339548505695},{0.30339480822304105,0.3244480749245895,0.3009338729033808},{0.30317324806214446,0.30229373550584926,0.31456133438858247},{0.29521462915265084,0.3080938153024133,0.3010962542469632},{0.3144179831870713,0.2879574155493217,0.2978213708654077},{0.31025523051789333,0.2955957013452813,0.30888982072032767},{0.30338192031545563,0.2982059910148621,0.2943908947246892},{0.28869664712721793,0.3121253382920619,0.3086433710752432},{0.30643672257164584,0.30837210845137775,0.30162586829051863},{0.28667344780469417,0.29669157718493994,0.30936471264525833},{0.30481281270161864,0.31970281390598204,0.2965399353976693},{0.296536646098754,0.31305268613771553,0.3059340704009694},{0.3069904548150618,0.30861115446149,0.2926707811676288},{0.2803309202868474,0.3006189258650122,0.30195701011116854},{0.3013327884454104,0.30630981089762965,0.29793955161808455},{0.3164973207371929,0.31347718925954926,0.2992729695049576},{0.29360490323563093,0.3189056843908781,0.31632406772777866},{0.2871537433924662,0.3009430747653776,0.28949494751491645},{0.2894979708977219,0.29431520121710425,0.29224346519172006},{0.3063380466097928,0.3017893775654164,0.2925079350282349},{0.31005423833292955,0.30318776818457793,0.29914276634422415},{0.30739677930022424,0.29583046577006367,0.2964305074152014},{0.31376895936781407,0.3039140310933986,0.32328343651632463},{0.2996755141671924,0.30482404406865393,0.2941814508756665},{0.30462992575297426,0.2891203673029685,0.303704514404009},{0.31105416332430563,0.2989685481922896,0.2877058630068502},{0.28538551881673396,0.28598586452997815,0.2912206267148431},{0.30550687916610336,0.29742597281522454,0.28751364413653707},{0.2896447518268974,0.2955164523802082,0.293683680718123},{0.28821402225158693,0.2966082971366524,0.2968158053691656},{0.3093632718350604,0.2951985845113628,0.29904261595189263},{0.3097290864711121,0.29272393428283944,0.29301598295363557},{0.29637518777725774,0.2994310623277653,0.2957659771318229},{0.28669466608122485,0.30280400528828344,0.3047867617709936},{0.29851265059289317,0.27876598047289897,0.30604077569191646},{0.2967916773012326,0.3073019426286334,0.3123632119165588},{0.3002290525927963,0.30416754429672754,0.31496042364848076},{0.2934558935485705,0.30970967767973273,0.2787759327011834},{0.28773447202802144,0.2979923042389158,0.293731911108468},{0.30371713264629147,0.2899952098448083,0.3000758192477859},{0.30476514797065474,0.2891509148094823,0.29715077512114607},{0.30001821084656605,0.3014082404516,0.2923460786579387},{0.2969361078974832,0.2870019057838788,0.30056459470689323},{0.3043629144347043,0.30744112042076027,0.3031227178847755},{0.31809157646468095,0.30868740338839684,0.2878506026334268},{0.29320146082515663,0.30475462407342885,0.29445193313832946},{0.29349751912546973,0.30740652492711074,0.31353089007888907},{0.28496146897677466,0.30956111567143285,0.2916255148505891},{0.29488985265230927,0.31070169276461973,0.28766787077148276},{0.2913000025640175,0.2886754103190522,0.2805058239373208},{0.3058132927184697,0.2865677634601124,0.32002270142731665},{0.29562458749429993,0.2824369877223047,0.28941801994169536},{0.2968196663092964,0.3212311051969198,0.297393021042414},{0.29385069930851215,0.2930263411533472,0.2888367640861479},{0.2970847726904766,0.2921349830608949,0.32739228243575436},{0.307487427750431,0.3138419932054241,0.2875685042073342},{0.29652227948379856,0.3152781577048291,0.29352399790728556},{0.28222538318495544,0.3039870223687642,0.2926418084525439},{0.28261863850660984,0.3011890261893985,0.2877739855533745},{0.30150152607086345,0.28843005431416746,0.30646774696822304},{0.3003069168391011,0.30339511899407,0.307515062512708},{0.30258684361443683,0.3012823706954088,0.28906906578444264},{0.3168157265335425,0.2832521133590054,0.2990020489260254},{0.30083514548534546,0.2772779984646919,0.3014658897757118},{0.2944430010113488,0.2860853330563233,0.29130399261151396},{0.30437908842329875,0.2917878872363157,0.298076815876406},{0.2973963257436626,0.3045569956374304,0.2839896473443803},{0.30073355053048517,0.299357565962201,0.30114547323729396},{0.31100707868088706,0.2982339842662087,0.29996882669398073},{0.28741866345087236,0.2979813982804462,0.3036797227725743},{0.2721103355979808,0.28780280058273017,0.2780197177643982},{0.2933843268957844,0.2983475677967271,0.2857954286215287},{0.30901198030807914,0.2986368827178018,0.28543157035248923},{0.3098532387917058,0.2838643410398938,0.3090150202169705},{0.29370873490556043,0.28837082298643335,0.3024079727634289},{0.3039980305410429,0.30281302896374146,0.3121292291791889},{0.3244354001845462,0.30702619810538906,0.2934488693395602},{0.28648234859986876,0.299865193373541,0.295324496134587},{0.2935482485345505,0.31574493047283053,0.30566582053479496},{0.294152148549753,0.29064314857033074,0.29298409640967743},{0.2829913220259885,0.3182645834826216,0.30108534565035866},{0.3089501420593702,0.2988138956218876,0.2917980310324947},{0.28921589272918824,0.30375022642719307,0.29383551139966424},{0.28703438992810854,0.29979181514199027,0.2994475659512351},{0.3175062785172205,0.2969841761242973,0.2852649764004023},{0.2885712584540356,0.3015952657247655,0.2698792479532671},{0.2985099140916851,0.2824665871459891,0.3028336924095},{0.3164340502913517,0.2854682449848419,0.29934947337352463},{0.3009773014413976,0.2925128067045106,0.3018377705224401},{0.2925323801350809,0.3000321264820926,0.3070069966442038},{0.2916910228779636,0.30576764209684143,0.3076736096180681},{0.30546518553008156,0.3008752662542616,0.2992377653849557},{0.27330232216558764,0.305088750179676,0.2939448301800751},{0.3107409338252069,0.2954643668114664,0.30610448365099946},{0.3043018943754901,0.2929731726109311,0.2916104740585381},{0.30431115947416704,0.3006537330578836,0.29092000624157366},{0.31194405158191846,0.30521726469865174,0.2989874153351755},{0.29548785114665543,0.31062915557123144,0.29723460012523684},{0.31532428642491056,0.299159378331006,0.3100173771224353},{0.29383878691673704,0.3106373332553132,0.3020213852659071},{0.29153328240857906,0.30449530344879794,0.2978952631354259},{0.29351228746986435,0.3056143149273394,0.29621560103252625},{0.3074049359142518,0.3028795482325267,0.2942109720730549},{0.3144123795136392,0.31235765208295246,0.3085144483237526},{0.2993309703322031,0.3028618977594908,0.28865065547814006},{0.2975878115790498,0.2904043757449303,0.2922287724464386},{0.3076873028838458,0.299129322538696,0.3117631534772165},{0.28305484059372704,0.2926212162514048,0.31980785514088644},{0.29050281952888524,0.30368080870514375,0.30351147100624},{0.3104685373660655,0.2877428359347777,0.28481709789935866},{0.30132646634042,0.2887065030742936,0.3140587904290185},{0.30852723648524855,0.3062687784042697,0.29731376240117535},{0.2898104817432298,0.2852512555844323,0.30031198631748973},{0.30042759076632863,0.2997297666812914,0.29271251429773404},{0.3326212485468232,0.2985595804868396,0.3091750707635308},{0.30798337945190707,0.3109620615737051,0.29638064327868907},{0.2963199960335244,0.2965356955500172,0.30155076126442976},{0.3025263947806874,0.29134821272673916,0.2838335869775256},{0.30414963714168775,0.3103031774254388,0.30889002453369535},{0.299621872737431,0.28890636905934997,0.2892292052809298},{0.3073511786043072,0.3078615976471131,0.30965748929672254},{0.3021668530956881,0.3244929222966551,0.3209436735167793},{0.2987430437343792,0.2826087681396241,0.3045358336925778},{0.28699232765643556,0.30753990618160393,0.3073369322053897},{0.3121753198772924,0.30731482088371154,0.2869718839211441},{0.2971954263789309,0.30946533323040176,0.29785930765738106},{0.30692206077390954,0.2977566193143211,0.31486309694958764},{0.3191001799281418,0.3084833991617014,0.30012936007355917},{0.2739649890685164,0.30744500115873163,0.2956093232098045},{0.2967354523013307,0.2884767382875436,0.3005770990669098},{0.30604691715666976,0.2945888604403086,0.3031371106271303},{0.3008335815898373,0.3194924490853138,0.3073234184040079},{0.30596955356684064,0.2973277665357703,0.283808264444719},{0.30483474324216,0.30697841543645915,0.2864547697551674},{0.3088051538381545,0.319691821759555,0.3190303546818431},{0.293495061575698,0.28081387234499544,0.2903604438099847},{0.3136810962483363,0.2888980863076542,0.284784232489686},{0.3090856205384922,0.29919911925452564,0.2996703209203579},{0.29998246726164846,0.30876251803445426,0.29707692297263616},{0.2985628672598355,0.2819553253068637,0.2999583323780221},{0.30924865672108437,0.2975001552446151,0.3106510489049729},{0.3032425134987815,0.3122245242989161,0.31304968233531166},{0.2983073783379909,0.3086781216947817,0.28975371143140755},{0.2880968028303669,0.3103551768970277,0.2919319551445552},{0.2974420974206762,0.2881647177419398,0.31632716236483366},{0.2818219682012511,0.27884023173472,0.30551696797578104},{0.29972658510385947,0.28788693316812475,0.2969449379562727},{0.2868900392315559,0.31493225572255473,0.30810588085174956},{0.29130649641450235,0.29748164473221905,0.3111277539351978},{0.29070374013705597,0.3081682893931706,0.3005467335684227},{0.3061445575429726,0.3089803326291584,0.2868533510959955},{0.30900118803034454,0.28747817508684825,0.30235978866574126},{0.30483886602258803,0.2864273105775484,0.32106418576570367},{0.30800047986784057,0.2853008063794154,0.3037614202882104},{0.2922013017796453,0.30106692819238673,0.3021177474218303},{0.3103520173537999,0.29786974568538355,0.2905479754182258},{0.30399267183335166,0.30333788297012215,0.2989467921337595},{0.3036109471575228,0.2988230247463079,0.2968576062466019},{0.30114357886076926,0.2910990933532576,0.30120480803630273},{0.2945466236013214,0.32472565208628795,0.279487502586512},{0.2803971890348576,0.30623772394755067,0.28679884171596887},{0.29835785664186115,0.29465603583742306,0.30129086653772036},{0.29827203941378116,0.2883765280127332,0.2782744339657897},{0.29299857796104456,0.31921726432508146,0.3095936074348577},{0.3046791174480264,0.2956946688539785,0.29088504006924126},{0.30542972149820746,0.2996251537252463,0.27878277990928063},{0.314249863912702,0.29520685565312366,0.32088075206683925},{0.2992782885183957,0.29762732442257583,0.3175738996581032},{0.28717973057691903,0.31603472271311694,0.29672660196079514},{0.3134893433330188,0.31783250676926944,0.3005773838723487},{0.2916162077583596,0.3008347851096752,0.29407047308850187},{0.3144048840734483,0.2919174512314119,0.30796032081792196},{0.279419197222515,0.3111696309196622,0.29758200035965693},{0.2950300021816338,0.3028400470994024,0.3027873508614317},{0.3058755865051657,0.2818659216598495,0.29516136859309167},{0.29043591227418547,0.2845532277426435,0.31114132732983873},{0.28705782451470313,0.2851086071770142,0.30621731463864926},{0.30069063342346314,0.29534674674073985,0.29369522016362404},{0.28661218625498913,0.3122726943158659,0.30547072776510614},{0.2978730953071234,0.30098579493584726,0.30782105573497953},{0.28906920258947333,0.3098055029169113,0.2883608058177041},{0.3011216556478479,0.283820691498627,0.32705446301491864},{0.2877285150809464,0.30305695509161057,0.3078431845921827},{0.2999633743927077,0.289844274108057,0.2822199394406878},{0.2984795839395461,0.2900562147065793,0.2998592222104249},{0.2878329578868036,0.27996405785852624,0.2917029091277247},{0.2908912421561711,0.2967321979180574,0.31029357615228653},{0.3027333351543521,0.28803569121149625,0.3178488802158522},{0.29638538153754745,0.2991966437359793,0.3051118867015964},{0.2751253194303668,0.2952258681701417,0.31856955916263296},{0.30390325549392355,0.2878821523163713,0.2988008831433603},{0.303656346272561,0.3063340134928332,0.2929145241767414},{0.292822434741422,0.30518765048682495,0.3057034253267371},{0.3016805052565016,0.2988051278113632,0.280547948863831},{0.2819116229086137,0.2864535789243539,0.29781874632505795},{0.29638213822485054,0.2870429666280052,0.29535520067045473},{0.2892755568893046,0.30570011838928013,0.30999112969567544},{0.29188421803296494,0.2946487158743813,0.3062051955725756},{0.30136597492085615,0.28893764149814405,0.2835134609156439},{0.29282760832954197,0.2970988092119174,0.30606757548414854},{0.2964807127188781,0.2935827352140595,0.30236087836766223},{0.30716864865336724,0.3011961498986313,0.30592309432366643},{0.28929126886275774,0.312069447801228,0.30307960707747106},{0.29533323660166283,0.30769535837686673,0.2927360522574421},{0.2856657783285847,0.3003204704591248,0.30131734844581065},{0.2931470298733389,0.3010290478589359,0.29492265495474446},{0.2912078723473907,0.2836006276502548,0.30799332937114504},{0.30299821139489497,0.30433701302335864,0.30851035873067567},{0.29335702239996525,0.3005534576876667,0.2993386240384921},{0.3060909142428531,0.3076706883284072,0.2884928643629232},{0.29345397357712033,0.28641755939139607,0.30194138997612374},{0.30354032117470375,0.28817464568100887,0.30104865624981986},{0.2931658881201478,0.29211023405330755,0.3086553878283168},{0.31102171296156866,0.31152090271571004,0.29315307548436886},{0.2831787273370596,0.2982960713197162,0.30104945401023603},{0.29523850845693406,0.3002139474680703,0.3218737915153606},{0.29031456779177245,0.3029081401258385,0.3097815307438466},{0.29560553082472907,0.3078438697588897,0.3135308958846159},{0.29703542659738846,0.2911843089658994,0.2970824857583485},{0.29449213886000575,0.3128180988821296,0.2949325428585173},{0.3199611452300093,0.2838609600042585,0.3184396268303755},{0.2993534024970725,0.28912348871617366,0.30534213381802516},{0.29461464022119305,0.27582017287107624,0.3063558554587931},{0.30736042305565703,0.3059352608131759,0.29357187249643174},{0.2841527946866009,0.3009022198270397,0.2993384560041816},{0.28895428886101565,0.29716078520295347,0.2824401882789703},{0.30293790550719996,0.2924501920037407,0.3185521717791999},{0.3034040180561869,0.2892240012525806,0.3045060488837038},{0.3082534286305143,0.3013946488255906,0.304027171000736},{0.29648232368998034,0.318615077251217,0.3264455773405779},{0.29767656124219877,0.2924957212866683,0.30096459736793146},{0.3113156808960741,0.28616812334966363,0.2900754086205635},{0.3009012305648495,0.2914765556500297,0.312754008222586},{0.2990853240223723,0.3067357348644867,0.2918024813394025},{0.3079697036952616,0.30509291346123485,0.30539443951949213},{0.3106242880638458,0.2990942167504435,0.30212618732744617},{0.2982820383752855,0.28910702159381113,0.27577573131966643},{0.283884298095607,0.3098522530019568,0.2952410995175945},{0.28985806652813395,0.306774452245812,0.30984650734466446},{0.29912840796506257,0.2976584905436091,0.30894881958897363},{0.31039313925484957,0.31743153975182536,0.31065520094853444},{0.28100534139944244,0.3028266174740242,0.30668848231296636},{0.31401434071202305,0.30339660175781735,0.29153629138485065},{0.29900878755053906,0.286435001460975,0.29929457870424747},{0.27852993404530557,0.3095068232408707,0.2997666293187403}};
                char* data_str = serialize(kirat_data, n);
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