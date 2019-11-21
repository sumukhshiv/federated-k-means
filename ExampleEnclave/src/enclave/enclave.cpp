#include "enclave_t.h"
#include <sgx_thread.h>
#include "__oblivious_impl.h"
#include "Oblivious.h"
#include <iostream>
#include <cassert>
#include <stdlib.h>
#include <stdio.h>
#include "kmeans.h"


struct node_t {
    uint32_t value;
    struct node_t* next;
    struct node_t* prev;
};

int current_i = 0;
int current_j = 0;
int global_dim = 0;
int total_rows = 0;

double static data_points[100][3];

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
    return 1;
}

void execute_k_means(int num_clusters) {
    int k = num_clusters;
    global_dim = 3;
    total_rows = 100;

    double weird_necessary_array[10][3];
    double cluster_initial[k][global_dim] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
    double cluster_final[k][global_dim];
    
    kmeans(global_dim, (double*)data_points, total_rows, k, (double*)cluster_initial, (int*) cluster_final);
}
