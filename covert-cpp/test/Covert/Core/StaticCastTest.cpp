// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<int, L> x;
SE<void *, H> vp;
SE<void **, H, L> vpp;
SE<int *, H, L> ip;
SE<int, L> *nonc;
int *k;

int main() {
  logd = &std::cout;
  TEST(se_static_cast<char *, H, L>(vp);) // CHECK: TEST
  // CHECK-NEXT: se_static_cast: 'SE<void*, H> &' -> 'SE<char*, H, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<char*, H, L>(char*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(se_static_cast<char **, H, H, L>(vp);) // CHECK: TEST
  // CHECK-NEXT: se_static_cast: 'SE<void*, H> &' -> 'SE<char**, H, H, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<char**, H, H, L>(char**)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(se_static_cast<void *, H>(vpp);) // CHECK: TEST
  // CHECK-NEXT: se_static_cast: 'SE<void**, H, L> &' -> 'SE<void*, H>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<void*, H>(void*)'{{$}}
  // CHECK-NEXT: END TEST

  // lvalue to lvalue conversion
  TEST(se_static_cast<int &, L>(x);) // CHECK: TEST
  // CHECK-NEXT: se_static_cast: 'SE<int, L> &' -> 'SE<int, L> &'{{$}}
  // CHECK-NEXT: END TEST

  // lvalue to xvalue conversion
  TEST(se_static_cast<int &&, L>(x);) // CHECK: TEST
  // CHECK-NEXT: se_static_cast: 'SE<int, L> &' -> 'SE<int, L> &&'{{$}}
  // CHECK-NEXT: END TEST

  // rvalue to xvalue conversion
  TEST(se_static_cast<int &&, L>(std::move(x));) // CHECK: TEST
  // CHECK-NEXT: se_static_cast: 'SE<int, L>' -> 'SE<int, L> &&'{{$}}
  // CHECK-NEXT: END TEST

  // cast a non-canonical value
  TEST(se_static_cast<int *, H, H>(nonc);) // CHECK: TEST
  // CHECK-NEXT: se_static_cast: 'SE<int, L>* &' -> 'SE<int*, H, H>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, H, H>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  // cast a primitive value
  TEST(se_static_cast<void *, H>(k);) // CHECK: TEST
  // CHECK-NEXT: se_static_cast: 'int* &' -> 'SE<void*, H>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<void*, H>(void*)'{{$}}
  // CHECK-NEXT: END TEST
}
