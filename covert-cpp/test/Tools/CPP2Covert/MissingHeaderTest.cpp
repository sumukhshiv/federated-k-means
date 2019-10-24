// RUN: %check-cpp2covert -checks=* --
// CHECK-MESSAGES: :[[@LINE-1]]:1: warning: Could not find header file 'SE.h'
// CHECK-FIXES: #include "Covert/SE.h"

int x = 0;
