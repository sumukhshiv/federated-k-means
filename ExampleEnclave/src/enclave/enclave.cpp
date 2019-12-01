#include "enclave_t.h"
#include <sgx_thread.h>
#include "__oblivious_impl.h"
#include "Oblivious.h"
#include <iostream>
#include <cassert>
#include <stdlib.h>
#include <stdio.h>
#include "kmeans.h"
#include "kmeans_nonobliv.h"
#include "enclave.h"
#include <cstring>
#include <string.h>
#include "data_testing_enclave.h"
using namespace std;

int current_i = 0;
int current_j = 0;
int global_dim = 0;
int total_rows = 0;
int total_calls = 0;

const int TEST_CONSTANT = 6; //TODO if you change this, also change this in app.cpp
const int OBLIV = 0;

//TODO Double hardcoded
 double static data_points[11520][3];
//  double static data_points[1440][3];
// double static data_points[720][3];
// double static data_points[360][3];
// double static data_points[180][3];
// double static data_points[90][3]; //TODO HARDCODED TO TOTAL NUM OF POINTS AND DIMENSION OF THE POINTS 

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
    total_calls++;
    if (total_calls == 3) {
        execute_k_means(3);
    }
    return 1;
}

double* deserialize(const char* my_str, int arr_len) {
    char my_char_array[sizeof(char)*strlen(my_str)+1];
    strncpy(my_char_array, my_str, sizeof(char)*strlen(my_str));
    char* chars_array = strtok(my_char_array, ",");
    int n= 12000;
    double deserialized_array[n]; // TODO: maxed out to 1000 numbers total (flattened version of the 2D array) - HARDCODED
    int i = 0;
    
    while(chars_array) {
        if (i > arr_len-1) {
            break;
        }
        deserialized_array[i] = atof(chars_array);
        chars_array = strtok(NULL, ",");
        i++;
    }

    double* to_ret = (double*)malloc(sizeof(double)*n);
    memcpy(to_ret, deserialized_array, sizeof(double)*n);
    return (double*) to_ret;
}

void execute_k_means(int num_clusters) {
    if (TEST_CONSTANT == 0) {
        global_dim = 3;   // TODO: HARDCODED dimension of points
        total_rows = 90; // TODO: HARDCODED total num of points recieved
        double weird_necessary_array[100][3];
        double cluster_initial[num_clusters][global_dim] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
        double cluster_final[num_clusters][global_dim];

        if (OBLIV) {
            kmeans(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        } else {
            kmeans_nonobliv(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        }

    } else if (TEST_CONSTANT == 1) {
        global_dim = 3;   // TODO: HARDCODED dimension of points
        total_rows = 180; // TODO: HARDCODED total num of points recieved
        double weird_necessary_array[100][3];
        double cluster_initial[num_clusters][global_dim] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
        double cluster_final[num_clusters][global_dim];

        if (OBLIV) {
            kmeans(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        } else {
            kmeans_nonobliv(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        }

    } else if (TEST_CONSTANT == 2) {
        global_dim = 3;   // TODO: HARDCODED dimension of points
        total_rows = 360; // TODO: HARDCODED total num of points recieved
        double weird_necessary_array[100][3];
        double cluster_initial[num_clusters][global_dim] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
        double cluster_final[num_clusters][global_dim];

        if (OBLIV) {
            kmeans(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        } else {
            kmeans_nonobliv(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        }

    } else if (TEST_CONSTANT == 3) {
        global_dim = 3;   // TODO: HARDCODED dimension of points
        total_rows = 720; // TODO: HARDCODED total num of points recieved
        double weird_necessary_array[1000][3];
        double cluster_initial[num_clusters][global_dim] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
        double cluster_final[num_clusters][global_dim];

        if (OBLIV) {
            kmeans(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        } else {
            kmeans_nonobliv(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        }

    } else if (TEST_CONSTANT == 4) {
        int n = 480;
        global_dim = 3;   // TODO: HARDCODED dimension of points
        total_rows = n*3; // TODO: HARDCODED total num of points recieved
        double weird_necessary_array[1000][3];
        double cluster_initial[num_clusters][global_dim] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
        double cluster_final[num_clusters][global_dim];

        if (OBLIV) {
            kmeans(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        } else {
            kmeans_nonobliv(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        }

    } else if (TEST_CONSTANT == 5) {
        int n = 960;
        global_dim = 3;   // TODO: HARDCODED dimension of points
        total_rows = n*3; // TODO: HARDCODED total num of points recieved
        double weird_necessary_array[1000][3];
        double cluster_initial[num_clusters][global_dim] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
        double cluster_final[num_clusters][global_dim];

        if (OBLIV) {
            kmeans(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        } else {
            kmeans_nonobliv(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        }

    } else if (TEST_CONSTANT == 6) {
        int n = 960*4;
        global_dim = 3;   // TODO: HARDCODED dimension of points
        total_rows = n*3; // TODO: HARDCODED total num of points recieved
        double weird_necessary_array[2000][3];
        double cluster_initial[num_clusters][global_dim] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
        double cluster_final[num_clusters][global_dim];

        if (OBLIV) {
            kmeans(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        } else {
            kmeans_nonobliv(global_dim, (double*)data_points, total_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);
        }

    }
}




