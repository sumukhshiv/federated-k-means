// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int x = 42;
SE<int *, L, L> xp = &x;
SE<int *, L, L> &rxp = xp;
SE<const int *, L, L> cxp = &x;

int main() {
  logd = &std::cout;
  TEST(SE<int, L> &rx = *xp;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>: Pointer dereference operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, L> &rx = *rxp;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>: Pointer dereference operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(const SE<int, L> &crx = *xp;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>: Pointer dereference operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(const SE<int, L> &crx = *cxp;) // CHECK: TEST
  // CHECK-NEXT: SE<const int*, L, L>: Pointer dereference operator{{$}}
  // CHECK-NEXT: END TEST
}
