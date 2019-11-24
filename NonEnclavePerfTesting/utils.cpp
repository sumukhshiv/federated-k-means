#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <time.h>
#include <string>
#include <string.h>
using namespace std;

char* serialize(double my_array[][3]) {
    string bar;
    bar = "";
    for(int i =0 ; i< 100;i++) {
        for(int j =0 ;j<3;j++) {
            bar += std::to_string(my_array[i][j]);
            bar += ',';
        }
    }
    char* to_ret = (char*)malloc(sizeof(char)*strlen(bar.c_str()));
    memcpy(to_ret, bar.c_str(), sizeof(char)*strlen(bar.c_str()));
    return to_ret;
}
