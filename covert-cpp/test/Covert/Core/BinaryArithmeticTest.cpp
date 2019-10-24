// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int x;
SE<long, H> l = 2;
SE<int, L> a = 2;
SE<int, L> &ra = a;
SE<int *, L, L> p;
SE<int *, H, L> q;

SE<unsigned int, H> hh = 12;
SE<short, L> ll = 30;

int main() {
  logd = &std::cout;
  TEST(ra = ra + a;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>, SE<int, L>: operator+{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<bool, H> r = l + a;) // CHECK: TEST
  // CHECK-NEXT: SE<long, H>, SE<int, L>: operator+{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<long, H>(long)'{{$}}
  // CHECK-NEXT: Converting constructor (Covert): 'SE<bool, H>(SE<long, H>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(auto r = hh + ll;) // CHECK: TEST
  // CHECK-NEXT: SE<unsigned int, H>, SE<short, L>: operator+{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<unsigned int, H>(unsigned int)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(auto r = p + l;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>, SE<long, H>: operator+{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, H, L>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(auto r = l + p;) // CHECK: TEST
  // CHECK-NEXT: SE<long, H>, SE<int*, L, L>: operator+{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, H, L>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(auto r = p + a;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>, SE<int, L>: operator+{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, L>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(auto r = p + x;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>, int: operator+{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, L>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(auto r = x + a;) // CHECK: TEST
  // CHECK-NEXT: int, SE<int, L>: operator+{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(auto r = a << a;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>, SE<int, L>: operator<<{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST
}
