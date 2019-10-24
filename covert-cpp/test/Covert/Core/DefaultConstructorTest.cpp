// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s
#include "Covert/SE.h"


// expected-no-diagnostics

enum E {};

void foo() {
  SE<int, L> basic;
  SE<enum E, L> _enum;
  SE<int *, L, L> pointer;
}
