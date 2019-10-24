// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

struct C {
  int x;
};
COVERT_LOG_TYPE(C);

C c;
SE<C *, L> cptr = &c;

int main() {
  logd = &std::cout;
  TEST(SE<void *, L> p = cptr;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (Covert): 'SE<void*, L>(SE<C*, L>)'
  // CHECK-NEXT: END TEST

  TEST(C &c = *cptr;) // CHECK: TEST
  // CHECK-NEXT: SE<C*, L>: Pointer dereference operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(C &c = cptr[0];) // CHECK: TEST
  // CHECK-NEXT: SE<C*, L>: Pointer index operator{{$}}
  // CHECK-NEXT: END TEST

  TEST(cptr->x = 1;) // CHECK: TEST
  // CHECK-NEXT: SE<C*, L>: Pointer member access operator{{$}}
  // CHECK-NEXT: END TEST
}
