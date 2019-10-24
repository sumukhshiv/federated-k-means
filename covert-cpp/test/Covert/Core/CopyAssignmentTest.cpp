// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int bar(int x) { return x; }

int x;
const SE<int, L> cx = 2;
SE<int, L> a;
SE<int *, L, L> p;
SE<int, L> &r = a;
SE<void *, L> c;

int main() {
  SE<int, L> b;
  SE<int *, L, L> q;
  SE<void *, L> pv;
  SE<int, H> h;

  logd = &std::cout;

  TEST(b = a;) // CHECK: TEST
  // CHECK-NEXT: END TEST

  TEST(q = p;) // CHECK: TEST
  // CHECK-NEXT: END TEST

  TEST(pv = p;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<void*, L>(SE<int*, L, L>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(h = a;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<int, H>(SE<int, L>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(r = cx;) // CHECK: TEST
  // CHECK-NEXT: END TEST
}
