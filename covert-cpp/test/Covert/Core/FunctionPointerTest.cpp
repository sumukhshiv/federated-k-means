// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<int *, L, L> foo(SE<int *, L, L> x, const SE<long, L> &i) {
  return x + i;
}

SE<int *, L, L> p;
SE<long, L> idx;

int main() {
  logd = &std::cout;
  SE<int *, L, L>(*fp)(SE<int *, L, L>, const SE<long, L> &) = &foo;
  TEST(int *(*_fp)(int *, const long &) = fp_cast(fp);) // CHECK: TEST
  // CHECK-NEXT: fp_cast: 'SE<int*, L, L>(*)(SE<int*, L, L>, const SE<long, L> &)' -> 'int*(*)(int*, const long &)'{{$}}
  // CHECK-NEXT: END TEST

  SE<int *, L, L> r = (*fp)(p, idx);
  SE<int *, L, L> r2 = fp(p, idx);
}
