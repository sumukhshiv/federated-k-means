// RUN: %check-cpp2covert -checks=* --

#include "Covert/SE.h"

class C {}
// CHECK-MESSAGES: :[[@LINE-1]]:11: error: {{.*}}

// Despite the error, processing should continue
int *k;
// CHECK-MESSAGES: :[[@LINE-1]]:6: warning: 'k' declared with primitive type 'int *'
// CHECK-FIXES: SE<int *, L, L> k;
