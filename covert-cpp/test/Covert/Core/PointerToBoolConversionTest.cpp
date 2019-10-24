// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int x;
SE<int *, L, L> flp = nullptr;
SE<int *, L, L> tlp = &x;
SE<int *, L, H> fhp = nullptr;
SE<int *, L, H> thp = &x;

int main() {
  logd = &std::cout;

  TEST(bool b = flp; assert(!b);) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int*, L, L>' -> 'int* &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(bool b = tlp; assert(b);) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int*, L, L>' -> 'int* &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(bool b = fhp; assert(!b);) // CHECK: TEST
  // CHECK-NEXT: Pointer to bool conversion: 'SE<int*, L, H>' -> 'bool'
  // CHECK-NEXT: END TEST

  TEST(bool b = thp; assert(b);) // CHECK: TEST
  // CHECK-NEXT: Pointer to bool conversion: 'SE<int*, L, H>' -> 'bool'
  // CHECK-NEXT: END TEST

}
