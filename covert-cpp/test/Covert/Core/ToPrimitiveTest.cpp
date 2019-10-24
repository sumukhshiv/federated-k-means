// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

int bar(int x) { return x; }

int x;
SE<int, H> a;
SE<int *, L, H> p;
SE<int, H> &r = a;
SE<int *, H, L> *pp;
SE<SE<int, H> *, L> *pp2;

int main() {
  logd = &std::cout;

  TEST(int b = se_to_primitive(a);) // CHECK: TEST
  // CHECK-NEXT: se_to_primitive: 'SE<int, H> &' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(short c = se_to_primitive(a);) // CHECK: TEST
  // CHECK-NEXT: se_to_primitive: 'SE<int, H> &' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int *q = se_to_primitive(p);) // CHECK: TEST
  // CHECK-NEXT: se_to_primitive: 'SE<int*, L, H> &' -> 'int* &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int s = se_to_primitive(r);) // CHECK: TEST
  // CHECK-NEXT: se_to_primitive: 'SE<int, H> &' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(const int cs = se_to_primitive(r);) // CHECK: TEST
  // CHECK-NEXT: se_to_primitive: 'SE<int, H> &' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int t = se_to_primitive(r);) // CHECK: TEST
  // CHECK-NEXT: se_to_primitive: 'SE<int, H> &' -> 'int &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int t = se_to_primitive(std::move(r));) // CHECK: TEST
  // CHECK-NEXT: se_to_primitive: 'SE<int, H>' -> 'int'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int **_pp = se_to_primitive(pp);) // CHECK: TEST
  // CHECK-NEXT: se_to_primitive: 'SE<int*, H, L>* &' -> 'int** &'{{$}}
  // CHECK-NEXT: END TEST

  TEST(int **_pp2 = se_to_primitive(pp2);) // CHECK: TEST
  // CHECK-NEXT: se_to_primitive: 'SE<SE<int, H>*, L>* &' -> 'int** &'{{$}}
  // CHECK-NEXT: END TEST
}
