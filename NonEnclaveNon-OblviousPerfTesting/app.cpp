#include <iostream>
#include <cassert>
#include <stdlib.h>
#include <stdio.h>
#include "kmeans_perf.h"
#include <cstring>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <assert.h>
#include "bank1_perf.h"
#include "bank2_perf.h"
#include "bank3_perf.h"
using namespace std;

struct node_t {
    uint32_t value;
    struct node_t* next;
    struct node_t* prev;
};

int current_i = 0;
int current_j = 0;
int total_rows = 0;
const int NUM_DATA_POINTS_AT_ONCE = 1000;
const int GLOBAL_DIM = 3;
const int NUM_CLUSTERS = 3;

double static data_points[3840][GLOBAL_DIM]; //TODO HARDCODED

const int TEST_CONSTANT = 6;


int storeData(double* data, int dim, int n) {
    total_rows += n;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < dim; j++) {
            data_points[current_i][current_j] = data[i*dim + j];
            current_j += 1;
        }
        current_j = 0;
        current_i += 1;
    }
    //printf("SIDHU");
    for (int i = 0; i < total_rows; i++) {
        for (int j = 0; j < 3; j++) {
            //printf("%f", data_points[i][j]);
        }
    }
    return 1;
}

double* deserialize(int num_points_bank, int dim, const char* my_str) {
    char my_char_array[sizeof(char)*strlen(my_str) + 1];
    strncpy(my_char_array, my_str, sizeof(char)*strlen(my_str));
    char* chars_array = strtok(my_char_array, ",");
    
    double deserialized_array[num_points_bank*dim];
    int i = 0;
    
    while(chars_array) {
        if (i >= num_points_bank*dim) {
            break;
        }
        deserialized_array[i] = atof(chars_array);
        chars_array = strtok(NULL, ",");
        i++;
    }
    double* to_ret = (double*)malloc(sizeof(double)*num_points_bank*dim);
    memcpy(to_ret, deserialized_array, sizeof(double)*num_points_bank*dim);
    return (double*) to_ret;
}

void execute_k_means(int num_clusters) {
    if (TEST_CONSTANT == 6) {
        int n = 960*4;
        int ttl_rows = n * 3;
        double weird_necessary_array[n][GLOBAL_DIM];
        double cluster_initial[num_clusters][GLOBAL_DIM] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
        double cluster_final[num_clusters][GLOBAL_DIM];
        kmeans(GLOBAL_DIM, (double*)data_points, ttl_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);

    } else if (TEST_CONSTANT == 5) {
        int n = 960;
        int ttl_rows = n * 3;
        double weird_necessary_array[n][GLOBAL_DIM];
        double cluster_initial[num_clusters][GLOBAL_DIM] = {{0.3, 0.3, 0.3}, {0.6, 0.6, 0.6}, {0.9, 0.9, 0.9}};
        double cluster_final[num_clusters][GLOBAL_DIM];
        kmeans(GLOBAL_DIM, (double*)data_points, ttl_rows, num_clusters, (double*)cluster_initial, (int*) cluster_final);

    }
    
}

int main(int argc, char const *argv[]) {
    // char* bank1_data = (char*)malloc(sizeof(char) * NUM_DATA_POINTS_AT_ONCE);
    char* num_points_bank1_str = send_data_1(GLOBAL_DIM);

    if (TEST_CONSTANT == 6) {
        int n = 960*4;
        double* bank_1_points = deserialize(n, GLOBAL_DIM, num_points_bank1_str);
        storeData(bank_1_points, GLOBAL_DIM, n);
        //free(bank1_data);

        // //printf("\n HERE\n");
        // char* bank2_data = (char*)malloc(sizeof(char) * NUM_DATA_POINTS_AT_ONCE);
        //char* num_points_bank2_str = send_data_2(GLOBAL_DIM);
        double* bank_2_points = deserialize(n, GLOBAL_DIM, num_points_bank2_str);
        storeData(bank_2_points, GLOBAL_DIM, n);
        // //free(bank2_data);

        char* bank3_data = (char*)malloc(sizeof(char) * NUM_DATA_POINTS_AT_ONCE);
        int num_points_bank3 = send_data_3(bank3_data, GLOBAL_DIM);
        double* bank_3_points = deserialize(num_points_bank3, GLOBAL_DIM, bank3_data);
        storeData(bank_3_points, GLOBAL_DIM, num_points_bank3);
        //free(bank3_data);
        
        execute_k_means(NUM_CLUSTERS);
    } else if (TEST_CONSTANT == 5) {
        int n = 1920;
        double* bank_1_points = deserialize(n, GLOBAL_DIM, num_points_bank1_str);
        storeData(bank_1_points, GLOBAL_DIM, n);
        //free(bank1_data);

        // //printf("\n HERE\n");
        // char* bank2_data = (char*)malloc(sizeof(char) * NUM_DATA_POINTS_AT_ONCE);
        char* num_points_bank2_str = send_data_2(GLOBAL_DIM);
        double* bank_2_points = deserialize(100, GLOBAL_DIM, num_points_bank2_str);
        storeData(bank_2_points, GLOBAL_DIM, 100);
        // //free(bank2_data);

        char* bank3_data = (char*)malloc(sizeof(char) * NUM_DATA_POINTS_AT_ONCE);
        int num_points_bank3 = send_data_3(bank3_data, GLOBAL_DIM);
        double* bank_3_points = deserialize(num_points_bank3, GLOBAL_DIM, bank3_data);
        storeData(bank_3_points, GLOBAL_DIM, num_points_bank3);
        //free(bank3_data);
        
        execute_k_means(NUM_CLUSTERS);

    }
    
    return 0;
}




