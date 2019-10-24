// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int arr[2] = {0, 1};
SE<int, H> sarr[2] = {0, 1};
SE<int *, L, L> lp = arr;
SE<int *, L, L> &rlp = lp;
SE<const int *, L, L> clp = arr;
SE<int *, L, H> hp = arr;

int main() {
  logd = &std::cout;
  TEST(SE<int, L> &a = lp[0];) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>: Pointer index operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, L> &a = rlp[0];) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>: Pointer index operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<short, L> as = lp[0];) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>: Pointer index operator{{$}}
  // CHECK-NEXT: Converting constructor (Covert): 'SE<short, L>(SE<int, L>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, H> ah = lp[0];) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>: Pointer index operator{{$}}
  // CHECK-NEXT: Converting constructor (Covert): 'SE<int, H>(SE<int, L>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, H> &ah = sarr[0];) // CHECK: TEST
  // CHECK-NEXT: END TEST

  TEST(SE<int, H> b = hp[0];) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, H>: Pointer index operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(const SE<int, L> &cb = clp[0];) // CHECK: TEST
  // CHECK-NEXT: SE<const int*, L, L>: Pointer index operator{{$}}
  // CHECK-NEXT: END TEST
}
