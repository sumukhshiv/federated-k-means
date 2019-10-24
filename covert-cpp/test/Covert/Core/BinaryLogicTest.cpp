// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

char c;
SE<long, H> l = 2;
SE<int, L> a = 2;
SE<int *, L, L> p;
SE<int *, H, L> q;

int main() {
  logd = &std::cout;
  TEST(SE<bool, H> ra = a < l;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>, SE<long, H>: operator<{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<bool, H> ra = a < c;) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>, char: operator<{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<char, L>(char)'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, L>(bool)'{{$}}
  // CHECK-NEXT: Converting constructor (Covert): 'SE<bool, H>(SE<bool, L>)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<bool, L> ra = c < a;) // CHECK: TEST
  // CHECK-NEXT: char, SE<int, L>: operator<{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<char, L>(char)'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, L>(bool)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<bool, H> r = p == q;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>, SE<int*, H, L>: operator=={{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'{{$}}
  // CHECK-NEXT: END TEST
}
