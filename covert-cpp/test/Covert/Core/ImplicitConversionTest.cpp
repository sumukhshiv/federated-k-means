// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int bar(int x) { return x; }

int x;
SE<int, L> a = 2;
const SE<double, L> d = 2.0;
const SE<int, L> ca = 4;
SE<int *, L, L> p;
const SE<int *, L, L> cp = p;
const SE<void *, L> cvp = cp;
SE<int, L> &r = a;

void foo(double) {}
void foo(bool) {}
void bar(int *) {}
void bar(bool) {}
void bar2(void *) {}
void bar2(bool) {}

int main() {
  logd = &std::cout;
  TEST(int b = a;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int &ra = a; ++ra; std::cout << (int)a << '\n';) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'{{$}}
  // CHECK: 3{{$}}
  // CHECK-NEXT: END TEST

  TEST(std::size_t c = a;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(const int &caa = ca;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (const reference): 'SE<int, L>' -> 'const int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int *q = (int *)p;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int*, L, L>' -> 'int* &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int &sr = r;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(const int &sa = a;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int &cs = r;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int t = r;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(new int[a];) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(switch (a) {}); // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(bar(cp);); // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (const reference): 'SE<int*, L, L>' -> 'const int* &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(bar2(cvp);); // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (const reference): 'SE<void*, L>' -> 'const void* &'{{$}}
  // CHECK-NEXT: END TEST

}
