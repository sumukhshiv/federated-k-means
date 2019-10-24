// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int bar(int x) { return x; }

int x;
SE<int, L> a;
SE<int *, L, L> p;
SE<int, L> &r = a;
SE<char *, L, L> c;

void foo(SE<char *, L, L>) {}
void foo(SE<char *, L, H>) {}
void bar(SE<char *, L, H>) {}

int main() {
  logd = &std::cout;
  TEST(SE<int, L> b = a;) // CHECK: TEST
  // CHECK-NEXT: END TEST

  TEST(SE<int *, L, L> q = p;) // CHECK: TEST
  // CHECK-NEXT: END TEST

  TEST(SE<int, L> &s = r;) // CHECK: TEST
  // CHECK-NEXT: END TEST

  TEST(foo(c);) // CHECK: TEST
  // CHECK-NEXT: END TEST

  TEST(const SE<int, L> &cr = r;) // CHECK: TEST
  // CHECK-NEXT: END TEST
}
