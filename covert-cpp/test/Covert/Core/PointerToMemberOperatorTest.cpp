// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

struct S {
  S(SE<int, L> n) : mi(n) {}
  mutable SE<int, L> mi;
  SE<int, L> f(SE<int, L> n) { return mi + n; }
};

struct D : public S {
  D(SE<int, L> n) : S(n) {}
};

COVERT_LOG_TYPE(S);
COVERT_LOG_TYPE(D);

int main() {
  SE<int, L>(S::*pf)(SE<int, L>) = &S::f;

  D d(7);
  SE<D *, L> pd = &d;

  logd = &std::cout;
  TEST((pd->*(pf))(8);) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<D*, L>' -> 'D* &'{{$}}
  // CHECK: END TEST
}
