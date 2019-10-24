// RUN: %check-cpp2covert -secret-only -checks=* --

#include "Covert/SE.h"

int not_secret = 0;
SECRET int secret = 1;
// CHECK-MESSAGES: :[[@LINE-1]]:12: warning: 'secret' declared with primitive type 'int'
// CHECK-FIXES: SECRET SE<int, H> secret = 1;
int *not_secret_p = nullptr;
SECRET int *secret_p = nullptr;
// CHECK-MESSAGES: :[[@LINE-1]]:13: warning: 'secret_p' declared with primitive type 'int *'
// CHECK-FIXES: SECRET SE<int *, L, H> secret_p = nullptr;
int arr[8];
SECRET int sarr[8];
// CHECK-MESSAGES: :[[@LINE-1]]:12: warning: 'sarr' declared with primitive type 'int [8]'
// CHECK-FIXES: SECRET SE<int, H> sarr[8];
