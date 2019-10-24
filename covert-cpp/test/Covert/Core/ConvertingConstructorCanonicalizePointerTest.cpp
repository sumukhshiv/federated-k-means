// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<int, L> *_pl;
SE<int, H> *_ph;
SE<SE<int, H> *, L> *_pph;

int main() {
  logd = &std::cout;

  TEST(SE<const void *, L> r = _pl;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (canonicalize pointer): 'SE<const void*, L>(SE<int, L>*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<const int *, H, L> r = _pl;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (canonicalize pointer): 'SE<const int*, H, L>(SE<int, L>*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<const int *, L, H> r = _ph;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (canonicalize pointer): 'SE<const int*, L, H>(SE<int, H>*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(SE<int **, L, L, H> r = _pph;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (canonicalize pointer): 'SE<int**, L, L, H>(SE<SE<int, H>*, L>*)'{{$}}
  // CHECK-NEXT: END TEST
}
