#include <stdio.h>
#include <iostream>
#include <assert.h>
#include "enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include "bank1.h"
#include "bank2.h"
#include "bank3.h"
#include "data_testing.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

const int TEST_CONSTANT = 1; //TODO if you change this, also change this in enclave.cpp

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

void ocall_print_double(double my_double) {
    printf("%f", my_double);
}

int main(int argc, char const *argv[]) {
    system("sgx_sign dump -enclave enclave.signed.so -dumpfile metadata_info.txt");
    if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    
    bank1_start_fn();
    bank2_start_fn();
    bank3_start_fn();
    return 0;
}
