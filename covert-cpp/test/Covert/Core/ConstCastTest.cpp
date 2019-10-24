// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

SE<const char *, L, L> p;
const auto cp = p;

int main() {
  logd = &std::cout;

  // rvalue to rvalue
  TEST(se_const_cast<char *, L, L>(std::move(p));) // CHECK: TEST
  // CHECK-NEXT: se_const_cast: 'SE<const char*, L, L>' -> 'SE<char*, L, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<char*, L, L>(char*)'{{$}}
  // CHECK-NEXT: END TEST

  // rvalue to rvalue reference
  TEST(se_const_cast<char *&&, L, L>(std::move(p));) // CHECK: TEST
  // CHECK-NEXT: se_const_cast: 'SE<const char*, L, L>' -> 'SE<char*, L, L> &&'{{$}}
  // CHECK-NEXT: END TEST

  // lvalue to rvalue
  TEST(se_const_cast<char *, L, L>(p);) // CHECK: TEST
  // CHECK-NEXT: se_const_cast: 'SE<const char*, L, L> &' -> 'SE<char*, L, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<char*, L, L>(char*)'{{$}}
  // CHECK-NEXT: END TEST

  // lvalue to lvalue reference
  TEST(se_const_cast<char *&, L, L>(cp);) // CHECK: TEST
  // CHECK-NEXT: se_const_cast: 'const SE<const char*, L, L> &' -> 'SE<char*, L, L> &'{{$}}
  // CHECK-NEXT: END TEST

  // lvalue to rvalue reference
  TEST(se_const_cast<char *&&, L, L>(cp);) // CHECK: TEST
  // CHECK-NEXT: se_const_cast: 'const SE<const char*, L, L> &' -> 'SE<char*, L, L> &&'{{$}}
  // CHECK-NEXT: END TEST
}
