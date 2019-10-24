// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<int, L> l;
SE<int, H> h;

int main() {
  logd = &std::cout;

  // test auto params
  auto lt = [](auto x, auto y) { return x < y; };
  TEST(auto res = lt(l, h);) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>, SE<int, H>: operator<{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'{{$}}
  // CHECK-NEXT: END TEST

  // test reference captures
  auto ltr = [&]() { return l < h; };
  TEST(auto res = ltr();) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>, SE<int, H>: operator<{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'{{$}}
  // CHECK-NEXT: END TEST

  // test copy captures
  auto ltc = [=]() { return l < h; };
  TEST(auto res = ltc();) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>, SE<int, H>: operator<{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'{{$}}
  // CHECK-NEXT: END TEST
}
