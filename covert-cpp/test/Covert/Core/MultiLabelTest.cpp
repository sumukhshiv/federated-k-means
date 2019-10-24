// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"
#include "../include/MPCLattice.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<int, H> h;

int main() {
  logd = &std::cout;
  TEST(MPC<SE<int, H> *, Bob> bpl = static_cast<SE<int, H> *>(&h);) // CHECK: TEST
  // CHECK-NEXT: SE<int, H>: Address of{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, H>(int*)'{{$}}
  // CHECK-NEXT: Implicit pointer decay: 'SE<int*, L, H>' -> 'SE<int, H>*'
  // CHECK-NEXT: Converting constructor (primitive): 'MPC<SE<int, H>*, Bob>(SE<int, H>*)'
  // CHECK-NEXT: END TEST
}
