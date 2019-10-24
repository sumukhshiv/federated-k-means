// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<int, H> a;
SE<int *, L, H> b;

int main() {
  logd = &std::cout;
  TEST(se_label_cast<int, L>(a);) // CHECK: TEST
  // CHECK-NEXT: se_label_cast: 'SE<int, H> &' -> 'SE<int, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(se_label_cast<int *, L, L>(b);) // CHECK: TEST
  // CHECK-NEXT: se_label_cast: 'SE<int*, L, H> &' -> 'SE<int*, L, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, L>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(se_label_cast<int &, L>(a);) // CHECK: TEST
  // CHECK-NEXT: se_label_cast: 'SE<int, H> &' -> 'SE<int, L> &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(se_label_cast<const int &, L>(a);) // CHECK: TEST
  // CHECK-NEXT: se_label_cast: 'SE<int, H> &' -> 'const SE<int, L> &'{{$}}
  // CHECK-NEXT: END TEST
}
