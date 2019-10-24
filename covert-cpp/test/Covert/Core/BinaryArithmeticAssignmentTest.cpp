// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<long, H> l = 2;
SE<int, L> a = 2;
SE<int, L> &ra = a;
SE<int *, L, L> p;

int main() {
  logd = &std::cout;
  TEST(SE<int, L> aa = a += 2;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>, int: operator+={{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, L> &_a = a += 2;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>, int: operator+={{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(ra += 2;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>, int: operator+={{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(p += 2;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>, int: operator+={{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(p -= a;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>, SE<int, L>: operator-={{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<long, H> &_L = l += a;) // CHECK: TEST
  // CHECK-NEXT: SE<long, H>, SE<int, L>: operator+={{$}}
  // CHECK-NEXT: END TEST
}
