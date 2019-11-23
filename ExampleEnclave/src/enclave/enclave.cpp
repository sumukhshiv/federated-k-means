#include "enclave_t.h"
#include <sgx_thread.h>
#include "__oblivious_impl.h"
#include "Oblivious.h"
#include <iostream>
#include <cassert>
#include <stdlib.h>
#include <stdio.h>
#include "kmeans.h"
#include "enclave.h"
#include <cstring>
#include <string.h>
using namespace std;

struct node_t {
    uint32_t value;
    struct node_t* next;
    struct node_t* prev;
};

int current_i = 0;
int current_j = 0;
int global_dim = 0;
int total_rows = 0;

double static data_points[200][3];

void init(){
    ocall_print("Initializing...");
}

int storeData(double* data, int dim, int n) {
    global_dim = dim; 
    total_rows += n;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < dim; j++) {
            data_points[current_i][current_j] = data[i*dim + j];
            current_j += 1;
        }
        current_j = 0;
        current_i += 1;
    }
    ocall_print("SIDHU");
    for (int i = 0; i < total_rows; i++) {
        for (int j = 0; j < 3; j++) {
            ocall_print_double(data_points[i][j]);
        }
    }
    return 1;
}

double* deserialize(const char* my_str) {
    char my_char_array[5000];
    strncpy(my_char_array, my_str, sizeof(char)*strlen(my_str));
    char* chars_array = strtok(my_char_array, ",");
    
    double deserialized_array[1000];
    int i = 0;
    
    while(chars_array) {
        if (i > 299) {
            break;
        }
        deserialized_array[i] = atof(chars_array);
        chars_array = strtok(NULL, ",");
        i++;
    }
    double* to_ret = (double*)malloc(sizeof(double)*1000);
    memcpy(to_ret, deserialized_array, sizeof(double)*1000);
    return (double*) to_ret;
}

void execute_k_means(int num_clusters) {
    global_dim = 3;
    total_rows = 200;

    double weird_necessary_array[100][3];
    double cluster_initial[num_clusters][global_dim] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
    double cluster_final[num_clusters][global_dim];

    kmeans(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
}




