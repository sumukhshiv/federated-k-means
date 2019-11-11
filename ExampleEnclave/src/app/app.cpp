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
    int dim = 3;
    int n = 100;

    double kirat_data[n][dim] = {{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0,0,0},{0.75,0.75,0.75},{0.2,0.2,0.2},{0.2,0.2,0.2},{0.2,0.2,0.2},{0.2,0.2,0.2},{0.2,0.2,0.2},{0.2,0.2,0.2},{0.2,0.2,0.2},{0.2,0.2,0.2},{0.2,0.2,0.2},{0.2,0.2,0.2}};

    sgx_status_t status = storeData(global_eid, &ptr, (double*)kirat_data, dim, n);
    // printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", status);
    assert (status == SGX_SUCCESS);

    status = execute_k_means(global_eid); 
    assert (status == SGX_SUCCESS);
    return 0;
}
