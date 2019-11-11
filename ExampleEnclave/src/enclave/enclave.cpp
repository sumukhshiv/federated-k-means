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
const int num_points = 9000;
const int num_dimensions = 17;
int current_i = 0;
int current_j = 0;
int global_dim = 0;
int total_rows = 0;

double static data_points[num_points][num_dimensions];

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
    double rand_arr[5] = {0.5, -0.2, 0.1, 0.4, -0.3};
    int rand_i = 0;
    int k = num_clusters;
    double cluster_initial[k][global_dim];
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < global_dim; j++) {
            cluster_initial[i][j] = rand_arr[rand_i];
            rand_i++;
            if (rand_i > 4) {
                rand_i = 0;
            }
        }
    }
    
    // cluster_initial[1][0] = 0.4;
    // cluster_initial[1][1] = 0.4;
    // cluster_initial[1][2] = 0.4;
    // cluster_initial[2][0] = 0.5;
    // cluster_initial[2][1] = 0.5;
    // cluster_initial[2][2] = 0.5;

    int cluster_final[k][global_dim];
    kmeans(global_dim, (double*) data_points, total_rows, k, (double*)cluster_initial, (int*) cluster_final);
}
