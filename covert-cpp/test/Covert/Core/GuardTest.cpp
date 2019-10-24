// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "../include/MPCLattice.h"
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

MPC<int, Public> x = 0;
MPC<int, Bob> b = 0;
MPC<int *, Bob, Bob> bp = &b;
char *cp = nullptr;
SE<const char *, L, H> ccp = cp;

int main() {
  logd = &std::cout;

  TEST(mpc_guard<Public>(x);) // CHECK: TEST
  // CHECK-NEXT: mpc_guard<Public>: 'MPC<int, Public> &'
  // CHECK-NEXT: END TEST

  TEST(mpc_guard<AliceBob>(x);) // CHECK: TEST
  // CHECK-NEXT: mpc_guard<AliceBob>: 'MPC<int, Public> &'
  // CHECK-NEXT: END TEST

  TEST(mpc_guard<AliceBob>(b);) // CHECK: TEST
  // CHECK-NEXT: mpc_guard<AliceBob>: 'MPC<int, Bob> &'
  // CHECK-NEXT: END TEST

  TEST(mpc_guard<Everyone>(b);) // CHECK: TEST
  // CHECK-NEXT: mpc_guard<Everyone>: 'MPC<int, Bob> &'
  // CHECK-NEXT: END TEST

  TEST(mpc_guard<Bob, Everyone>(bp);) // CHECK: TEST
  // CHECK-NEXT: mpc_guard<Bob, Everyone>: 'MPC<int*, Bob, Bob> &'
  // CHECK-NEXT: END TEST

  TEST(mpc_guard<Everyone, Bob>(bp);) // CHECK: TEST
  // CHECK-NEXT: mpc_guard<Everyone, Bob>: 'MPC<int*, Bob, Bob> &'
  // CHECK-NEXT: END TEST

  TEST(se_guard<L, L>(cp);) // CHECK: TEST
  // CHECK-NEXT: se_guard<L, L>: 'char* &'
  // CHECK-NEXT: END TEST

  TEST(se_guard<H, H>(ccp);) // CHECK: TEST
  // CHECK-NEXT: se_guard<H, H>: 'SE<const char*, L, H> &'
  // CHECK-NEXT: END TEST
}
