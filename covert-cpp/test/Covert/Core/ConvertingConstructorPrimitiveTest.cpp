// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int x = 42;
unsigned short y = 43;

int main() {
  logd = &std::cout;
  TEST(SE<int, L> basic = x;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int *, L, L> pointer = &x;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, L>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int *, L, L> pointer2 = 0;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, L>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<const char *, L, L> str = "Hello, world!";) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<const char*, L, L>(const char*)'{{$}}
  // CHECK-NEXT: END TEST
}
