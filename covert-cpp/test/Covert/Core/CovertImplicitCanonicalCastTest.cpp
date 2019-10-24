// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<int *, L, L> p;
SE<int **, L, L, L> pp;

int main() {
  logd = &std::cout;

  TEST(SE<int, H> *_p = p;) // CHECK: TEST
  // CHECK-NEXT: Implicit Covert canonical conversion (pointer): 'SE<int*, L, L>' -> 'SE<int, H>*'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, L> *_p = p;) // CHECK: TEST
  // CHECK-NEXT: Implicit Covert canonical conversion (pointer): 'SE<int*, L, L>' -> 'SE<int, L>*'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, L> **_pp = pp;) // CHECK: TEST
  // CHECK-NEXT: Implicit Covert canonical conversion (pointer): 'SE<int**, L, L, L>' -> 'SE<int, L>**'{{$}}
  // CHECK-NEXT: END TEST
}
