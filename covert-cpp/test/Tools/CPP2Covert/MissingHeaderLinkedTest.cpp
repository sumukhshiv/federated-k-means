// RUN: %check-cpp2covert -linked-with-covert -checks=* --
// CHECK-MESSAGES: :[[@LINE-1]]:1: warning: Could not find header file 'SE.h'
// CHECK-FIXES: #include "SE.h"

int x = 0;
