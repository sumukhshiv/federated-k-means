#include <stdio.h>
#include <iostream>
#include <assert.h>
#include "enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include "__oblivious_impl.h"
#include "Oblivious.h"
#include "oarray.h"


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

int main(int argc, char const *argv[]) {
    oblivious::oarray<int, 256> _arr;
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    int ptr;
    sgx_status_t status = generate_random_number(global_eid, &ptr);
    std::cout << status << std::endl;
    if (status != SGX_SUCCESS) {
        std::cout << "noob" << std::endl;
    }
    printf("Random number: %d\n", ptr);

    int dim = 3;
    int n = 2;
    //double kirat_data[4] = {2.0, 2.0, 2.0, 2.0};
    double kirat_data[n][dim];

    // kirat_data[0][0] = 2.0;
    // kirat_data[0][1] = 1.0;
    // kirat_data[1][0] = 2.0;
    // kirat_data[1][1] = 1.0;
    kirat_data[0][0] = 7.0;
    kirat_data[0][1] = 20.0;
    kirat_data[0][2] = 8.0;
    kirat_data[1][0] = 7.0;
    kirat_data[1][1] = 20.0;
    kirat_data[1][2] = 9.0;
    // double* kirat = (double*) kirat_data;
    // for (int i = 0; i < n; i++) {
    //     for (int j = 0; j < dim; j++) {
    //         printf("%f", kirat[i*dim + j]);
    //     }
    // }
    status = storeData(global_eid, &ptr, (double*)kirat_data, dim, n);
    // printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", status);
    assert (status == SGX_SUCCESS);

    status = add_number(global_eid, &ptr, 10); 
    assert (ptr);
    assert (status == SGX_SUCCESS);

    status = add_number(global_eid, &ptr, 20); 
    assert (ptr);
    assert (status == SGX_SUCCESS);

    status = add_number(global_eid, &ptr, 30); 
    assert (ptr);
    assert (status == SGX_SUCCESS);

    status = add_number(global_eid, &ptr, 30); 
    assert (ptr);
    assert (status == SGX_SUCCESS);

    status = add_number(global_eid, &ptr, 40); 
    assert (ptr);
    assert (status == SGX_SUCCESS);

    status = del_number(global_eid, &ptr, 30); 
    assert (ptr);
    assert (status == SGX_SUCCESS);

    uint32_t sum;
    status = get_sum(global_eid, &sum); 
    printf("Sum: %u\n", sum);
    assert (status == SGX_SUCCESS);

    // // Seal the random number
    // size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
    // uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    // sgx_status_t ecall_status;
    // status = seal(global_eid, &ecall_status,
    //         (uint8_t*)&ptr, sizeof(ptr),
    //         (sgx_sealed_data_t*)sealed_data, sealed_size);

    // if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
    //     return 1;
    // }

    // int unsealed;
    // status = unseal(global_eid, &ecall_status,
    //         (sgx_sealed_data_t*)sealed_data, sealed_size,
    //         (uint8_t*)&unsealed, sizeof(unsealed));

    // if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) {
    //     return 1;
    // }

    // std::cout << "Seal round trip success! Receive back " << unsealed << std::endl;

    return 0;
}
