// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<int *, L, L> p;

int main() {
  logd = &std::cout;
  TEST(SE<bool, L> pp = !p;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>: operator!{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, L>(bool)'{{$}}
  // CHECK-NEXT: END TEST
}
