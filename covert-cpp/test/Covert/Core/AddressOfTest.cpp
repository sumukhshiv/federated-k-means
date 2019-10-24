// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int x;
SE<int, L> l;
const SE<int, L> cl = 4;
SE<int, H> h;
SE<int, L> &xr = l;

int main() {
  logd = &std::cout;
  TEST(SE<int *, L, L> pl = &l;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>: Address of{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, L>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int *, L, H> ph = &h;) // CHECK: TEST
  // CHECK-NEXT: SE<int, H>: Address of{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, H>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int *, L, L> pxr = &xr;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>: Address of{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, L>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<const int *, L, L> pcl = &cl;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>: Address of (const){{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<const int*, L, L>(const int*)'{{$}}
  // CHECK-NEXT: END TEST
}
