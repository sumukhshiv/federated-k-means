// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<int, L> a = 2;
SE<int, L> &ra = a;
SE<int *, L, L> p;

int main() {
  logd = &std::cout;
  TEST(SE<int, L> aa = -a;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>: operator-{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, L> aa = ~a;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>: operator~{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST
}
