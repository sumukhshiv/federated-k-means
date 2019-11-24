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
            } else if (TEST_CONSTANT == 4) {
                double kirat_data[480][3] = {{0.2864041609751514,0.3077803631091051,0.31084492047569956},{0.29619654950191227,0.29014058471094045,0.2982753621144072},{0.3003803472322903,0.29449773557199227,0.29601320553514715},{0.28798825806323897,0.3017960642114968,0.30926977437586517},{0.2967906121096622,0.3143154195978978,0.3036185986567091},{0.28563185653974105,0.29958732569053476,0.31877073648274956},{0.3015701422109654,0.31381341839761895,0.3040217565428135},{0.3094034826046529,0.31156856893177465,0.29785076120412624},{0.2980948014123361,0.2907818277555831,0.2754420033315785},{0.32056342126431914,0.3029179898927203,0.2774405363565941},{0.2927808129825695,0.3086664779147365,0.296210859577034},{0.283493485937041,0.28287896206972063,0.2874828221660018},{0.296447009865178,0.2940632678155867,0.3018277156040432},{0.30236163323097104,0.3045548705921276,0.28866986884205487},{0.2953685415359009,0.31589465655286614,0.2969706037929696},{0.29557978200304746,0.29937370469697766,0.3072065943759752},{0.3153741212672629,0.2949536402696402,0.2893100051020717},{0.297292974664131,0.30889450935703316,0.299790853635609},{0.287448899807089,0.2848267498389656,0.31713727225448896},{0.29679911630760764,0.3112685774237045,0.3210487139175285},{0.28916692896037727,0.28626738690833065,0.3024203829700211},{0.2717276823691003,0.29017404401595975,0.29805910806238656},{0.31759707952604355,0.29518278456294533,0.28627834055571605},{0.30241983962040336,0.31942970189989306,0.3026309811780334},{0.2988714883198027,0.32254880492775406,0.3145777343180178},{0.31371839071488905,0.2961831486438948,0.30279258584767177},{0.2948764510903685,0.31168566256224495,0.29882199064489634},{0.2870920589863996,0.29384247037324623,0.2819762874733313},{0.30583244864956444,0.29834271967350884,0.3069629502030821},{0.30612053225690283,0.3009370174805251,0.2927615431492245},{0.28496733423889675,0.3185521138061959,0.3098844046087683},{0.30169760067958395,0.3018137230121557,0.30360354100495657},{0.30155330409442027,0.2914467475103008,0.30264004475843925},{0.2891595378301807,0.2950991441198832,0.29548976804682797},{0.3161134025974443,0.3113451349864942,0.30805538955586015},{0.3007667673922008,0.2886841785094453,0.30204327418424626},{0.29088908061613095,0.30425010607556424,0.3068174379835184},{0.31605217237744365,0.2942517079485397,0.2820936190243053},{0.3155849976571838,0.29522082407392086,0.30208521931155713},{0.28421593675974033,0.2999539365816148,0.3003598557542821},{0.31170362787567324,0.3130774281511612,0.3089050106633736},{0.2824739437920777,0.31614884228333767,0.2956412104753767},{0.28780706454182625,0.30913050376657913,0.29637083474686926},{0.28593379642721084,0.3128385674837229,0.2963443770879978},{0.30645172748747046,0.3003450329679085,0.297399576351684},{0.31030419479496785,0.2783234927669185,0.2800453788882815},{0.3151118302624115,0.3080456324456085,0.3090518311839907},{0.3000551806223602,0.3065449716233628,0.31101386233342543},{0.31252164153445045,0.30947857468346185,0.30480930069767176},{0.3205015068639798,0.3202206363730296,0.2973807866832612},{0.28644576482716316,0.2989808645472066,0.309290353335513},{0.29781355513300806,0.30135383134168237,0.3098762419507576},{0.3101867397947451,0.3002851492493479,0.30282295512972174},{0.2969006435819399,0.30227391251029445,0.3026914175522346},{0.287289445829518,0.29262942530157293,0.3082880709559369},{0.29816860226013936,0.2980353778996906,0.2928720063516779},{0.2955387709858949,0.33878477440165455,0.27856412846319406},{0.2914749764411066,0.2969581954213169,0.28361608522837906},{0.29863339299938896,0.3115641859365859,0.30037258866168587},{0.30698353461383027,0.29605082967477014,0.29291184893986966},{0.2941489524485521,0.30194224136615416,0.28806093223064977},{0.3086218525271663,0.29809134469685067,0.29134152221075127},{0.29024779905308357,0.32325572318647133,0.30580599192749475},{0.282385028204935,0.31326535155552016,0.3025842591387869},{0.2920813148541395,0.2826088889007054,0.2996083354330258},{0.28248244869661715,0.2946062844311538,0.29918357166793597},{0.2814498503087928,0.3013088415436233,0.2981822773911302},{0.2972096904504014,0.30127277303812383,0.3037196290449084},{0.31355008490021713,0.30488528154733907,0.2917805850998194},{0.2950021599199713,0.29806180934884596,0.3303767591209658},{0.3113781751745122,0.2934394493562934,0.29305381514584994},{0.2819456278683554,0.30634703498795135,0.2972089251146474},{0.3101680343338606,0.3172437869807102,0.3089669397821422},{0.2943485480040989,0.2979678072042452,0.29215533740330235},{0.3170629053408612,0.3053528913855781,0.3140258310438819},{0.3198493493517603,0.31248339746689385,0.28941941704772856},{0.29742167595818386,0.2946409646227,0.3102496416600734},{0.30893295034482404,0.32164256030283706,0.30692452440154155},{0.28990818276394364,0.28978159936745795,0.2902251681595491},{0.290473119102221,0.29419320053495557,0.3007691395653778},{0.2896992086465726,0.31698670163951725,0.2895991383556444},{0.3013962767700265,0.2948616760441771,0.2928358210511167},{0.29018330315451296,0.3130829450756312,0.29053235860334137},{0.29264160113186394,0.30350880165935423,0.308950070795297},{0.293749913596756,0.2938569099210787,0.30551188263694834},{0.30850480983017864,0.2973974145159574,0.29148638868376525},{0.30545549893769836,0.2805126968184896,0.3107186567198098},{0.31758450578056835,0.3023422503271233,0.30303928425887633},{0.3078605846123034,0.29457205189100794,0.3215854483040163},{0.29341883867941665,0.297589718762054,0.305748118502911},{0.32041204547068436,0.3058900821599471,0.28491420528089645},{0.2960182328857493,0.2921225091064906,0.3122381380926558},{0.2958144270898782,0.2918111703041785,0.3004123885193285},{0.2970129238329021,0.3013271916953425,0.30099682217019436},{0.293684431463186,0.30632334640395725,0.3081771451773736},{0.30112795469277764,0.30112599218145103,0.30353496141266995},{0.2946068484968464,0.2898209738566717,0.30506562268205034},{0.3017272885718796,0.29943371429940757,0.3033532553424986},{0.30165760336848907,0.2997838189362196,0.30451933613138227},{0.30339568759491947,0.30833991071246153,0.3067930396817708},{0.3007361863718356,0.29329750525386367,0.292964468708799},{0.298360386659992,0.3195351836687681,0.3036637278903876},{0.2790814919625721,0.3159048775451511,0.29750299483363324},{0.30849765662998196,0.2860358793046437,0.3064564865134866},{0.29556671835282505,0.3071991932042671,0.26388819998341423},{0.3027855875996954,0.30443404629915527,0.30745934883225445},{0.2992366927628993,0.2990834284330836,0.29258772967608876},{0.3031485517957938,0.28358667583150976,0.277347281631048},{0.28791595415364074,0.31048863167415114,0.32577882001886516},{0.30731499843798554,0.3019433123367423,0.299876155950005},{0.30950356416110625,0.30070449892594636,0.2858747254122985},{0.3001681380890442,0.31035565362271406,0.31160452358950624},{0.3200612011157913,0.3226596278148077,0.3144718485175272},{0.3100563489822423,0.3057710773254155,0.3213580488652016},{0.27699680789392755,0.2874445313570323,0.29307194543623094},{0.31966524222489845,0.29832962654371514,0.3173159055090968},{0.3101563541626157,0.2974697614033728,0.3053699347154386},{0.28889746128231314,0.29887607691178203,0.3094547572420088},{0.2919203646338765,0.30242110039328585,0.30083141627235316},{0.28656381998146846,0.29562509482513855,0.3129811255174718},{0.30433795030838096,0.3004623179457185,0.29590147217659213},{0.30072170313939306,0.31111366451229205,0.29755669628224596},{0.2824406319653827,0.29683002393762065,0.2903487684532476},{0.29856347255074106,0.3147651202324542,0.3050009876181099},{0.2864533648150463,0.3113862177753913,0.3083900849040183},{0.27934025813278635,0.3021996525231848,0.29261738255301023},{0.2941616672379212,0.3199624285750018,0.3024851521187718},{0.32747070287033025,0.3182086820242269,0.31235055266921347},{0.2908984588278732,0.29727050175569864,0.30377378168453967},{0.29326015225965113,0.30861339734775106,0.312750441305264},{0.2973558025210344,0.2954526605497708,0.28531739320428373},{0.29173477726204977,0.2982095378708833,0.3147756677058651},{0.29814907124207773,0.2844479018257208,0.28762908172905716},{0.29939068275597913,0.2951027770374721,0.3070119835447805},{0.30751107743676315,0.2944342514508693,0.31099252542348366},{0.3071312364065379,0.292013209451242,0.3067509756283581},{0.30406786428560195,0.29008239335866826,0.3087068950481612},{0.29796016439680284,0.30795714191546425,0.30024171012361495},{0.2941632123389561,0.2905070773251993,0.3159942603106428},{0.3063409422613895,0.3118550676610658,0.28993743522392196},{0.3126120826462045,0.28798265864196426,0.32808736022967966},{0.30144491159998144,0.2805575067070045,0.28584567497673147},{0.29726835488449366,0.3108385418926179,0.29365439644328134},{0.2952703696607601,0.30882311538573237,0.299063006713492},{0.32444089390100395,0.30460436922149925,0.28095778837304614},{0.30630115795275614,0.2974088449446948,0.30521632594623155},{0.30207715414632974,0.29789738462063,0.29377681655303983},{0.2906417130085379,0.3053223448614398,0.29001317131330023},{0.30582125394330917,0.2919316426168161,0.302461491904828},{0.29938384059778356,0.3041184064973825,0.30884923020172295},{0.29835038292542154,0.3059442595846871,0.3086097248435637},{0.2931659578774103,0.2850384062379911,0.31152162024385943},{0.30745742207816334,0.30510415766952786,0.3023351176894745},{0.29414869771382324,0.29448201408770314,0.29973775185601703},{0.31238900347566384,0.319917499910988,0.31019313896548834},{0.2874983630210064,0.3007546576918055,0.30202466119028704},{0.3056394503125309,0.30540161261933685,0.3007099049742385},{0.29551350591656833,0.29030521798328135,0.30949684109028985},{0.2974712500990261,0.32595519471185297,0.31857881313332387},{0.2998676946356997,0.31170442415942057,0.2945802000014394},{0.29299525523614905,0.2993283935860304,0.30200832452539356},{0.2936356079982317,0.29895516983676673,0.29739370974365287},{0.29909481269309085,0.2893121543435122,0.28753069636914913},{0.29970894218503985,0.29617223533009945,0.28419183194163133},{0.3056618530591524,0.3132131378205803,0.28760442387690527},{0.28463196310165756,0.29919740265382305,0.29468902490044013},{0.30176813552692466,0.2853540543680421,0.2935902262685548},{0.309452802556566,0.3204463861565898,0.29044733130056755},{0.30144855841526785,0.2785046481436242,0.31775497677476494},{0.29752049211530307,0.3069097025812242,0.3047879137708867},{0.29908932269986904,0.30323957583042194,0.282632778977719},{0.3023141319420347,0.30330249394740433,0.30532315480523164},{0.2948585743451744,0.3046643030829708,0.2975162597182188},{0.28929449932772805,0.3109932533621621,0.28905024623953385},{0.3056573236338673,0.3033611210755396,0.29680536428278104},{0.297611126756535,0.2991590558687868,0.315133920785639},{0.3035795678897298,0.3104105537814328,0.29301954020576443},{0.321174149809298,0.30643502677964485,0.28126954487203515},{0.30336086764810033,0.3049146265405255,0.30200510509883516},{0.28567499680683783,0.30263450937899483,0.29533254444630136},{0.28638513428007745,0.28559870292758793,0.3016659264464274},{0.2929208473579065,0.29203110992273273,0.3078665820898181},{0.29316233061885155,0.2980538328072991,0.30354884770601276},{0.297865609081016,0.306335839280142,0.29960352701457915},{0.30497763495565805,0.30532701281654345,0.29624619314924},{0.2760129664608477,0.3199061113726358,0.287744869906876},{0.3034423882249404,0.2990588414254448,0.311188535020761},{0.2804899217036594,0.3039781938126346,0.2992127352824461},{0.3115903740164595,0.2994605574109631,0.3190265816674262},{0.3127640592979529,0.2926645551387233,0.29358361625342166},{0.30464059932723364,0.2927702256499046,0.31437062736629784},{0.29439817364758536,0.30923747349934194,0.2909115865464343},{0.3037834051893787,0.31038910935564473,0.2950689547058816},{0.3099236877127074,0.2942036211192648,0.2910345410630723},{0.2971603807913248,0.30180727251887385,0.3073452572924303},{0.3070951882108159,0.30411708640214946,0.2799094779211309},{0.2933454049494789,0.31339770326318395,0.2982971254443834},{0.2954071290445552,0.30831054936734525,0.31263331346998946},{0.28342972212648604,0.2924086634451012,0.2974515347515773},{0.2915451514586575,0.2856887305715213,0.3000117675785288},{0.3012952218200366,0.29153871881888277,0.2992693493480105},{0.28536805545048977,0.31799273048061444,0.32277359866177796},{0.2817273891101377,0.3050706404209459,0.29340462278490687},{0.3095134718749814,0.30689237916586554,0.3051158345345942},{0.31983711303879103,0.31688971120986054,0.2976874401604865},{0.3074452293053751,0.28990867061382686,0.2987100712933744},{0.30946252680549724,0.32087329849676305,0.288486607130419},{0.2990310103670029,0.31940052550442477,0.28578521260387685},{0.28798844206290086,0.3076511662147937,0.3067454382529533},{0.2955238916061532,0.2894433274852911,0.28699601306578015},{0.3050248059842643,0.3057390045223717,0.2858771587814398},{0.29962308621755557,0.30574780751419967,0.29795528161126766},{0.28097874500188863,0.3096213708082134,0.2869907889736613},{0.31519674855936336,0.2981074788292622,0.3034065475700587},{0.3030785876602752,0.3000402824290507,0.2897378190956206},{0.2875172151711338,0.30298354036030445,0.32451920809570695},{0.31358644309854056,0.3066835310369543,0.2751655940125774},{0.2965455862455168,0.3051221076924249,0.2817062710251472},{0.2901866187398689,0.30848391376689,0.2928142019669751},{0.3030301600884641,0.2938373283936769,0.28174214653971413},{0.30472818187087664,0.2994200702912461,0.29672113710146475},{0.3047517860729615,0.31788255846941227,0.2992132623289878},{0.2828758850384746,0.2871644404381661,0.313430311197023},{0.3098285150041705,0.2967944048046411,0.29962954848191026},{0.31547151117088496,0.3151767634597967,0.29071830940817406},{0.2933758660572331,0.3000600039685813,0.314551800740723},{0.2771130350119567,0.29116703849221337,0.31030237963831714},{0.32295217367210893,0.2854739587704015,0.3146272897632795},{0.2977266884385605,0.2980252745856539,0.30896287598258},{0.2943866588511081,0.31284188303248295,0.3117426353744682},{0.31170115543448135,0.29356281945161594,0.31053663196510733},{0.3061553071098204,0.2923700634333167,0.2847450031826177},{0.3014556984634788,0.30697119173981663,0.30183467642433287},{0.29823809364711956,0.305615877290064,0.28748307128034956},{0.30431202029757143,0.31250211381933324,0.30538636466758645},{0.2996663136138097,0.2895657185243981,0.2996781274608423},{0.2872297320502284,0.28278013093641746,0.2956924661532601},{0.3063506092807986,0.32150638118924574,0.2845370093059963},{0.2940614465676775,0.31087364397256584,0.29463116859435606},{0.31046211171179605,0.31142781838455114,0.2971226949104048},{0.3047644411695765,0.2976054233906528,0.2905759434687944},{0.2959925237985652,0.2947287614047233,0.3008782631673627},{0.29550975027657705,0.29293810572084383,0.2941253449017635},{0.30116139906648914,0.29147778952140935,0.30593712484962293},{0.2984290977372654,0.29425663512838296,0.3129334282330895},{0.3031144281332577,0.2985871397336651,0.32552004322320094},{0.30624224889282353,0.3144079395654894,0.2979332846899852},{0.30870341266337487,0.283598916880096,0.29007782151066136},{0.31682342785855905,0.3095718672884649,0.2939498793963069},{0.3112547545235562,0.30359731333525597,0.3056519374559115},{0.29629069826736293,0.29894618155388053,0.2988641981856525},{0.2830399024261484,0.29065056188170274,0.29463068714916435},{0.3064606263919693,0.302170002420733,0.29169764797925285},{0.3024252603676963,0.3158354094189156,0.3004186871979843},{0.2934960529102991,0.30792904326128717,0.28739926891802786},{0.3082366236503254,0.3017691426207187,0.31175538336979997},{0.28721357431921185,0.3088633627729725,0.29213219684227254},{0.30528903466981133,0.2907791886175049,0.30688419856198174},{0.2839532050031669,0.2947661371998427,0.28735976327093177},{0.29212221392646054,0.29753944044617997,0.3066708975546664},{0.30422721431981015,0.2968863824184442,0.31063509616925583},{0.3133700160957455,0.3057357119480472,0.294680073313446},{0.29240142332402347,0.3036395039652796,0.2891689915894208},{0.2917017708500129,0.30447798028467654,0.3169758774634245},{0.28027484556436477,0.3011939421412115,0.29333455851778445},{0.3055246728134322,0.2992930922906059,0.30813547980646017},{0.29905990562115387,0.3020178494993424,0.2881419354527922},{0.303730037772311,0.2977997175269083,0.29138866384514694},{0.3058211520332786,0.30538829016534363,0.2974369679249952},{0.302581091305581,0.3145042371886755,0.30038505260033593},{0.3032130355511909,0.2896781512677536,0.32892191383213465},{0.3134410447618292,0.30222851156129665,0.29891661877658454},{0.29312841449887833,0.2997382870274373,0.2856953838456606},{0.3063940615092901,0.2951297202402783,0.3013670123304002},{0.3041935175736628,0.31199052292213497,0.30256583408244087},{0.3086143373304742,0.3215353459437537,0.2928065540715524},{0.3040493680736773,0.312203246946527,0.299735100137145},{0.28877588918183283,0.2958862222601608,0.29119918243513554},{0.29371359478220227,0.31893009570411834,0.29606103256383476},{0.2933107287535159,0.30021735423360046,0.2904301226428342},{0.3021098197393157,0.30300148425583984,0.29448284223526067},{0.3084774150985282,0.29035854696269314,0.2895782163501428},{0.3078716431986271,0.30536781635258775,0.296345040736607},{0.3019479389288301,0.29320815477211193,0.2948791692416156},{0.30214215419678875,0.2980827813211042,0.2984120392890015},{0.30026232563091826,0.30006916453104193,0.28734272529200083},{0.31681626366280197,0.3090055763431383,0.29368147763847496},{0.2943539755530681,0.31250248998532804,0.29970258119080806},{0.2915802265298811,0.31267921608953103,0.28238553278933776},{0.2834618592148798,0.3012367610097983,0.30627949103580354},{0.3075568503080669,0.3157701364267994,0.2839007184968815},{0.29434980876276756,0.3032458351187748,0.2785278745504767},{0.3082523488096471,0.30976173467485973,0.3058206956222628},{0.28328198122090226,0.2929537240656819,0.3030399568746877},{0.28250489738026047,0.28955517291648797,0.3083392408806596},{0.29305008038128094,0.30832295869293064,0.2997254429111777},{0.29792937731034325,0.2873533556272726,0.316503022774492},{0.28249668229888464,0.30638614165661027,0.29940313799669294},{0.30686750024535486,0.3018559794471977,0.30375743908992164},{0.2957304747682625,0.2862820667116964,0.2995856544011095},{0.2881665533138036,0.29785665171864684,0.3121967170796345},{0.2885139232989102,0.3064279102576235,0.28598266436003744},{0.2900391819744435,0.30762513941154346,0.3138936098241557},{0.3066156990831245,0.313139547629171,0.303150442085296},{0.30093679679555285,0.2853282931256511,0.30880935027700623},{0.29938212849196777,0.3140180270284402,0.2975455895237273},{0.299094327386475,0.2897898249654167,0.2957508033245469},{0.30085262876108715,0.28792690423840467,0.292889906870554},{0.3071722274783415,0.30216683076490114,0.2904101301149248},{0.3086560444176997,0.3121520372645579,0.3008125590817967},{0.3031705974234778,0.3146255288843183,0.30939405020566546},{0.2979211479450921,0.2971430139017138,0.30357769713454025},{0.30138514277272316,0.29677495619924965,0.3234127820414465},{0.3048362243281599,0.2931131643290224,0.2997353117035808},{0.29915673548163574,0.3053819863996638,0.30534029160053155},{0.3164445477126778,0.3076214072937932,0.2981737081897697},{0.3178738074824452,0.31396602195253953,0.29438455796461327},{0.29112090685892505,0.2892178696672539,0.2857257943135932},{0.2888761759536273,0.30879727958971354,0.30619166905388706},{0.30006586801807955,0.3026828516343571,0.2962848087914267},{0.2844298098840193,0.30347736811837694,0.3127437009007161},{0.29980628761665096,0.3123805449207046,0.3059068719708397},{0.2981856218723159,0.3008036738281117,0.3080990580858288},{0.3170427391594282,0.3079737641303931,0.3087611945574856},{0.2967758499142768,0.30979463347643316,0.2927715022249455},{0.30981526897936096,0.3055899461062434,0.31237892651144444},{0.3167174658804802,0.30154787301337893,0.30937395169611226},{0.2901829551251116,0.3015367433550889,0.29686292381491863},{0.29291278813663446,0.29174452827833497,0.3056633326018541},{0.30114987125754783,0.2844280787841655,0.2925193778860437},{0.2947016546262689,0.30381721301652764,0.2870191260987754},{0.2864007454398962,0.29987928542683656,0.2956883174091742},{0.31301810579089245,0.30699207315252974,0.2941478286988063},{0.30233272625494445,0.3073753995726547,0.28714139085234086},{0.29803439854249564,0.29810562167898014,0.30952421576012445},{0.29587069729896537,0.30791706477577757,0.29254630934988374},{0.3083221800719118,0.30068960166811104,0.2842492556447115},{0.31485881423609324,0.2909172760238288,0.322611582301215},{0.3007885523518429,0.29382700742975015,0.30225918703665566},{0.3021903931123238,0.3084768519605659,0.2842038087330879},{0.3163891231818182,0.3194421077177083,0.3014499547749972},{0.2907996931996176,0.30594310806528435,0.31576717676966887},{0.30745766403859764,0.3043318038843026,0.30591590800600266},{0.3112738556895306,0.2987510706632228,0.28150188624716255},{0.3158107341087291,0.3054630291904246,0.3098298007058218},{0.3008010687731245,0.3063327255193647,0.2865479388781006},{0.32291831404766785,0.30407529009828593,0.3107812065681555},{0.2991391283636157,0.2988980419424961,0.30318550827981905},{0.29320896139023156,0.27897301820044823,0.2934411573106935},{0.2987649459034306,0.3007239893464958,0.2976315235275724},{0.30646960925663047,0.3084070095786638,0.29811558952792333},{0.31826524040738335,0.315668334848847,0.29128216008554714},{0.30885311376736396,0.3038041668300242,0.29064224013845946},{0.2984723564448625,0.2808792952395582,0.284696804126756},{0.31643805712634027,0.2867172073932561,0.30271298298811583},{0.3078843053076188,0.29117129133988123,0.2990931940422587},{0.28621966746074884,0.286491138630129,0.2863132291950268},{0.31035836063128347,0.3008262410865341,0.29435824364652613},{0.3076342189651313,0.2932127896069906,0.2835302696617636},{0.31269845633902466,0.29849506838460477,0.3235893649634765},{0.29159280265185555,0.3017121492979505,0.29322955630882},{0.2999658903839635,0.3200430580330361,0.3077998214207624},{0.3057809516253645,0.28862725059248,0.30444223944536447},{0.30165728850375695,0.3077860839277912,0.29240008449593485},{0.2945954562004349,0.3127816823459126,0.2990570478413912},{0.31072214739894194,0.3000469722981632,0.29291922300362805},{0.29806149337810445,0.3011262684077405,0.2888601944671249},{0.2948633899449654,0.30419637860486937,0.31287264536458387},{0.29104438105229724,0.2863212356183219,0.29181781896378445},{0.3166347696725363,0.29512564025696786,0.2984834289858658},{0.29387566482247435,0.3021381285262813,0.3188915682403486},{0.32789090078938626,0.30683229287841185,0.2905013959414534},{0.3026182129299514,0.2968771121482876,0.2974245665781879},{0.297592496998038,0.29075609374746664,0.28609253611470836},{0.2907893000294166,0.29352329114430475,0.2902398276196542},{0.29960622286843835,0.28967044443670914,0.298493324736256},{0.30809758740006554,0.312113082244846,0.29065134402321835},{0.29550701551889214,0.2870172455696256,0.29009153868510645},{0.3038089969292565,0.28794884587635877,0.30566457011275405},{0.31523150507944836,0.3108093137521883,0.3038170044131145},{0.3118574774225349,0.3046540908035179,0.30196317424942626},{0.2916652870378669,0.2918557435412221,0.2921650999966828},{0.30300142943543396,0.3017281436123213,0.30925492832820517},{0.2907488369767055,0.30348558355353505,0.31731632406232985},{0.2858221649612599,0.30727876382955827,0.2814206585324881},{0.28716252107924445,0.2907882714155636,0.29381764698566787},{0.30470357773198575,0.29889237565763344,0.31172728353857665},{0.3025546808168236,0.29521567779594626,0.3139099841984224},{0.3228923172214447,0.29768109136257415,0.30035387664532304},{0.2823386257333398,0.308525122635589,0.30765520370535154},{0.31307705308461325,0.3109740755611706,0.31284845490318214},{0.297358663611122,0.2997697215541711,0.31072764538770203},{0.3048645974162177,0.3120584379689057,0.28601763739627856},{0.28929447583008167,0.30105708700419614,0.29273779518136545},{0.29706131922923645,0.27906342424368286,0.28465005122960446},{0.3099136529199307,0.30049860768897824,0.2951650133940744},{0.28945383250397366,0.28356397511390835,0.29945837704806944},{0.2972511753527464,0.30115469019447105,0.3047143476552275},{0.306732318110102,0.30261529075834737,0.29265704643809604},{0.29775030137869124,0.3007985960594719,0.31808836122208767},{0.2984635948969899,0.30238432754689737,0.3198933045259325},{0.2983798802639579,0.29832939686965027,0.3062213903644825},{0.30774792918893734,0.28353212593886534,0.28683177296562384},{0.3197591635154388,0.3144070088002762,0.3195923766789952},{0.28285532143443015,0.30804885311167085,0.3041627880178153},{0.28219017935148405,0.30747237468628563,0.29945816817996623},{0.30165715786641084,0.291123947294596,0.2837324013504192},{0.2908270285119422,0.30860123102072357,0.29920350238548177},{0.291840714520871,0.2967689600550468,0.2858678612224304},{0.2906714358690901,0.28461442714348856,0.3115277742897476},{0.2881696592024826,0.3078244526676888,0.30799734410336876},{0.29404844877002795,0.30623025271418897,0.2937410671295286},{0.29224782072666006,0.29440820242366733,0.29647076609942347},{0.2868055351491931,0.29754234096236976,0.3096291822812581},{0.29765193471531465,0.29026943193577665,0.3174843569997416},{0.3082312984820256,0.30177467327064855,0.2894087849847908},{0.3107137808576708,0.2863441239478437,0.31928986423652433},{0.2917772149665617,0.2865966526674959,0.3047541358335346},{0.30547687089208353,0.2942489087448771,0.30345461161614856},{0.2981831138963914,0.30126755554244083,0.30320886172524825},{0.2987404462474323,0.29211581779281093,0.3129956865264466},{0.2894835631885558,0.28873967529477923,0.28967228814852614},{0.3178967854140382,0.31342599426633144,0.2986568854074753},{0.32429269078639,0.29935270650340967,0.27679723517896154},{0.30141304067274727,0.2973334743615125,0.3086734511616129},{0.2927334476343122,0.2929466728789756,0.2930506021186038},{0.29126565146290023,0.3063642389870489,0.3047520251510539},{0.2863026288998915,0.29503439427474704,0.3005750195241531},{0.30249244386067303,0.30070334082046396,0.3074504084912686},{0.3075719235456288,0.3142415857973079,0.29733459531232775},{0.3156309784812456,0.2996636864613173,0.2992312395715217},{0.30189520603004094,0.2860321019515945,0.3146347731425853},{0.3161864581210609,0.3107704123862,0.31248318124061686},{0.3010790587273521,0.3119041555065654,0.2979330985384573},{0.28816356936339044,0.3100360086233291,0.31010811519078924},{0.2933410230289896,0.308279807008903,0.297907008110129},{0.3007536011209462,0.3058513518262304,0.28262172275256386},{0.30452933169394975,0.3222340579828358,0.3009960204977682},{0.3206165519697222,0.30518106306276277,0.2971167986683483},{0.2997853633078585,0.29516429259357513,0.3094547020810399},{0.3051084517860248,0.29630631906935506,0.28600892817281515},{0.31096535346338083,0.29277378541548765,0.31142421023162536},{0.2745787499642151,0.3092127755237515,0.2920028857297411},{0.29703836103296594,0.3092120636336621,0.282612790044948},{0.29236411453544275,0.29730703250537277,0.30450988414310887},{0.30224811070337604,0.2969815648791727,0.29569675416639296},{0.3003037327086354,0.3009163644346407,0.3049481604448634},{0.3059858554421275,0.3102085012004559,0.27789540695220694},{0.29666704374034086,0.31072450614308395,0.3025323992185549},{0.3064123531417622,0.29608308238183473,0.3003038133095438},{0.29190515331927464,0.30060196595141964,0.3109193693303499},{0.3073089629457655,0.30475470401210725,0.28896076533158516},{0.31150777569072297,0.2918800774736774,0.30028934503258214},{0.29135397522052214,0.2943540410301819,0.2956634828484479},{0.28339466189230145,0.29167240415535783,0.2845211486382578},{0.31269933535892125,0.298496079913134,0.30385140188738613},{0.3114946253164895,0.292964185554343,0.30516948141266437},{0.2783974959928163,0.300695598291747,0.2936601908049891},{0.3046635997844809,0.3051257999204593,0.28740971663768977},{0.2918893141906758,0.29032257488276725,0.2982616380193368},{0.3093772709006052,0.31967530948754197,0.2855167309365206},{0.2896588492533989,0.28449782597357587,0.3073743741861913},{0.30112988708057853,0.2903168753572979,0.29415936088198924},{0.2880289800562641,0.3119697941714884,0.30423087380450153},{0.3034287377406295,0.3014314314735997,0.2949804177555953},{0.30752936263822045,0.29417205337772234,0.2887373557381604},{0.2903659664720799,0.2920431823483859,0.29147976561175437},{0.2945973639448164,0.31735162936961614,0.30520684066112597},{0.3004869891021558,0.2952066688568085,0.29580616627438794},{0.31016708862443987,0.30061707340635097,0.2985608109732908},{0.29614112839297513,0.2991422405546675,0.2877406420704425},{0.31064524325402115,0.29336538182670974,0.28512520674422104},{0.30871917629662005,0.29887288490988867,0.29098162406189404},{0.29574955194658153,0.28801307987378844,0.2935099559871474},{0.29156329027913597,0.30988926596237604,0.30064825774836623},{0.3028294804030258,0.3145325900925519,0.29875084459177204},{0.3119901918382098,0.3069435061947217,0.2854343176521246},{0.29936534193851677,0.30889344750419123,0.2917314935577731},{0.3067143815318903,0.29355219579054487,0.29226838759765955},{0.3268957660669055,0.3011012495117817,0.3155981706357678}};
                char* data_str = serialize(kirat_data, 480);
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