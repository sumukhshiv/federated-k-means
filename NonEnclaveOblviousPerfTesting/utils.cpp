#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string>
#include <string.h>
#include <iostream>
using namespace std;

char* serialize(double my_array[][3]) {
    string bar;
    bar = "kirat";
    //printf("INSIDE BEGINNING OF SERIALIZE\n");
    // printf("my_array[1][0] is %s\n", ); 
    for(int i=0 ; i < 100; i++) {
        //printf("STARTING I %d\n", i);    
        for(int j=0; j < 3; j++) {
            //printf("STARTING J %d\n", j);    
            // printf("I AND J : %d, %d", i, j);
            // std::cout << std::to_string(my_array[i][j]) << '\n';
            // std::cout << bar << '\n';
            // std::cout << bar + std::to_string(my_array[i][j]) << '\n';
            double elem = my_array[i][j];
            bar = bar + std::to_string(elem);
            //printf("ENDING J %d\n", j);    
            bar += ',';
        }
    }
    //printf("INSIDE SERIALIZE AFTER FOR LOOP\n");    

    char* to_ret = (char*)malloc(sizeof(char)*strlen(bar.c_str()));
    memcpy(to_ret, bar.c_str(), sizeof(char)*strlen(bar.c_str()));
    return to_ret;
}
