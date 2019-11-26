#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string>
#include <string.h>
#include <iostream>
using namespace std;

char* serialize(double my_array[][3], int num_points) {
    string bar;
    bar = "";
    for(int i=0 ; i < num_points; i++) {
        for(int j=0; j < 3; j++) {
            double elem = my_array[i][j];
            bar = bar + std::to_string(elem);
            bar += ',';
        }
    }
    //printf("INSIDE SERIALIZE AFTER FOR LOOP\n");    

    char* to_ret = (char*)malloc(sizeof(char)*strlen(bar.c_str()));
    memcpy(to_ret, bar.c_str(), sizeof(char)*strlen(bar.c_str()));
    return to_ret;
}
