// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

struct S {
  SE<int, L> x;
} s;
S cs {2};
SE<S *, L> ps = &s;
SE<S *, L> &rps = ps;
const SE<const S *, L> cps = &cs;

COVERT_LOG_TYPE(S);

int main() {
  logd = &std::cout;
  TEST(SE<int, L> &a = ps->x;) // CHECK: TEST
  // CHECK-NEXT: SE<S*, L>: Pointer member access operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int, L> &a = rps->x;) // CHECK: TEST
  // CHECK-NEXT: SE<S*, L>: Pointer member access operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(const SE<int, L> &a = cps->x;) // CHECK: TEST
  // CHECK-NEXT: SE<const S*, L>: Pointer member access operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(ps->x = 3; *logd << (int)s.x << '\n';) // CHECK: TEST
  // CHECK: SE<S*, L>: Pointer member access operator{{$}}
  // CHECK: 3
  // CHECK-NEXT: END TEST
}
