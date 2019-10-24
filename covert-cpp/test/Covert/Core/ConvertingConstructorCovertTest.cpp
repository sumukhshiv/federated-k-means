// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int bar(int x) { return x; }

SE<int, L> a;
SE<int, H> ha;
SE<bool, H> hb;
SE<int *, H, L> p;
SE<char *, L, L> cp;

void bar(SE<char *, L, H>) {}

SE<SE<int, L> *, L> ph;
SE<SE<int *, L, H> *, H> pph;

SE<int *, L, L> ip;
SE<int, L> x;

int main() {
  logd = &std::cout;

  TEST(SE<bool, H> r = ha;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<bool, H>(SE<int, H>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, H> r = hb;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<int, H>(SE<bool, H>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<long, L> r = x;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<long, L>(SE<int, L>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<void *, L> r = ip;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<void*, L>(SE<int*, L, L>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<const int *, L, L> r = ph;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<const int*, L, L>(SE<SE<int, L>*, L>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int **, H, L, H> r = pph;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<int**, H, L, H>(SE<SE<int*, L, H>*, H>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int *, H, H> r = p;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<int*, H, H>(SE<int*, H, L>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, H> r = a;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<int, H>(SE<int, L>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(bar(cp);) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<char*, L, H>(SE<char*, L, L>)'{{$}}
  // CHECK-NEXT: END TEST
}
