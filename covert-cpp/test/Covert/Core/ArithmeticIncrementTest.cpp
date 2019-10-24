// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int a = 2, b;
SE<int, L> &ra = reinterpret_cast<SE<int, L> &>(a);
SE<int *, L, L> p;

int main() {
  logd = &std::cout;
  TEST(++ra; *logd << "a: " << a << '\n';) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>: operator++ (prefix){{$}}
  // CHECK-NEXT: a: 3{{$}}
  // CHECK-NEXT: END TEST

  TEST(b = ra--; *logd << "a: " << a << '\n'; *logd << "b: " << b << '\n';) // CHECK: TEST
  // CHECK-NEXT: SE<int, L>: operator-- (postfix){{$}}
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'{{$}}
  // CHECK-NEXT: a: 2{{$}}
  // CHECK-NEXT: b: 3{{$}}
  // CHECK-NEXT: END TEST

  TEST(p++;) // CHECK: TEST
  // CHECK-NEXT: SE<int*, L, L>: operator++ (postfix){{$}}
  // CHECK-NEXT: END TEST
}
