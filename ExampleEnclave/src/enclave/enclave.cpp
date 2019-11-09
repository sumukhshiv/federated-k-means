#include "enclave_t.h"
#include <sgx_thread.h>
#include "__oblivious_impl.h"
#include "Oblivious.h"
#include <iostream>
#include <cassert>
#include <stdlib.h>
#include <stdio.h>
#include "kmeans.h"
//#include "oarray.h"


struct node_t {
    uint32_t value;
    struct node_t* next;
    struct node_t* prev;
};
const int num_points = 1000;
const int num_dimensions = 3;
int current_i = 0;
int current_j = 0;
int global_dim = 0;
int total_rows = 0;

double static data_points[num_points][num_dimensions];


void init(){
    ocall_print("HELLO");
}

int storeData(double* data, int dim, int n){
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

void execute_k_means() {
    int k = 3;
    double cluster_initial[k][global_dim];
    cluster_initial[0][0] = 0.3;
    cluster_initial[0][1] = 0.3;
    cluster_initial[0][2] = 0.3;
    cluster_initial[1][0] = 0.4;
    cluster_initial[1][1] = 0.4;
    cluster_initial[1][2] = 0.4;
    cluster_initial[2][0] = 0.5;
    cluster_initial[2][1] = 0.5;
    cluster_initial[2][2] = 0.5;
    

    int cluster_final[k][global_dim];

    kmeans(global_dim, (double*) data_points, total_rows, k, (double*)cluster_initial, (int*) cluster_final);
    ocall_print("HARKIRAT SINGH SIDHU");
}

void print_data_array() {
    for (int i = current_i - 1; i > 0; i--) {
        char* row = (char*) malloc(1000);
        snprintf(row, 1000, "%f, %f, %f\n", data_points[i][0], data_points[i][1], data_points[i][2]);
        ocall_print(row);
    }
}

int generate_random_number() {
     // oarray<int, 256> _arr;
    ocall_print("Processing random number generation...");
    if (o_copy_i64(1, 4, 5) == 4) {
        ocall_print("MY NAME IS KIRAT");
    } else {
        ocall_print("GG DUDE");
    }

  //  runKirat();



    return 42;
}

struct node_t * head = NULL;
struct node_t * tail = NULL;

int add_number(uint32_t value) {
    struct node_t* new_node = (struct node_t*) malloc(sizeof(node_t));

    sgx_thread_mutex_t mutex;
    sgx_thread_mutexattr_t attr;

    sgx_thread_mutex_init(&mutex, &attr);
    sgx_thread_mutex_lock(&mutex);

    if (new_node == NULL) {
        return 0;
    }
    new_node->value = value;
    new_node->next = NULL;
    new_node->prev = NULL;

    if (head == NULL) {
        head = tail = new_node;
    } else {
        tail->next = new_node;
        new_node->prev = tail;
        tail = new_node;
    }

    sgx_thread_mutex_unlock(&mutex);
    sgx_thread_mutex_destroy(&mutex);
    return 1;
}

int del_number(uint32_t value) {
    // list empty? 
    if (head == NULL) {
        return 0;
    }

    // does list have only one node?
    if (head == tail) {
        if (head->value == value) {
            free(head);
            head = tail = NULL;
            return 1;
        } else {
            return 0;
        }
    }

    // list has many nodes.
    struct node_t* ptr;
    for (ptr = head; ptr != NULL; ptr = ptr->next) {
        if (ptr->value == value) {
            ptr->prev->next = ptr->next;
            if (ptr->next != NULL) {
                ptr->next->prev = ptr->prev;
            }
            free (ptr);
            return 1;
        }
    }
    return 0;
}

uint32_t get_sum(void) {
    struct node_t* ptr;
    uint32_t sum = 0;
    for (ptr = head; ptr != NULL; ptr = ptr->next) {
        sum += ptr->value;
    }
    return sum;
}
