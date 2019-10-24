// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<int, L> arr[4] = {0, 1, 2, 3};

void foo(SE<void *, L> p) {}

int main() {
  logd = &std::cout;

  TEST(SE<int *, L, L> r = arr;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (canonicalize pointer): 'SE<int*, L, L>(SE<int, L>*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<const int *, L, L> r = arr;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (canonicalize pointer): 'SE<const int*, L, L>(SE<int, L>*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(foo(arr);) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (canonicalize pointer): 'SE<void*, L>(SE<int, L>*)'{{$}}
  // CHECK-NEXT: END TEST
}
