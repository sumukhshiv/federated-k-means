// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int x;
SE<int, L> a;

int bar() { return x; }
SE<int, L> foo() { return a; }

int main() {
  logd = &std::cout;
  TEST(int r = (foo(), x);) // CHECK: TEST
  // CHECK-NEXT: END TEST

  TEST(SE<int, L> r = (bar(), foo());) // CHECK: TEST
  // CHECK-NEXT: END TEST

  TEST(SE<int, H> r = (foo(), foo());) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<int, H>(SE<int, L>)'{{$}}
  // CHECK-NEXT: END TEST
}
