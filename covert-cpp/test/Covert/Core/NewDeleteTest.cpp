// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

struct Base {
  Base() {
    *logd << "Base Constructor\n";
  }
  virtual ~Base() {
    *logd << "Base Destructor\n";
  }
};
struct Derived : Base {
  Derived() : Base() {
    *logd << "Derived Constructor\n";
  }
  virtual ~Derived() {
    *logd << "Derived Destructor\n";
  }
};

COVERT_LOG_TYPE(Base);
COVERT_LOG_TYPE(Derived);

SE<Base *, L> bp;
SE<int *, L, H> iph;
SE<int *, L, L> ipl;

int main() {
  logd = &std::cout;
  SE<int, H> *xx = iph;
  TEST(bp = new Derived;) // CHECK: TEST
  // CHECK-NEXT: Base Constructor{{$}}
  // CHECK-NEXT: Derived Constructor{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<Base*, L>(Base*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(delete bp;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<Base*, L>' -> 'Base* &'
  // CHECK-NEXT: Derived Destructor{{$}}
  // CHECK-NEXT: Base Destructor{{$}}
  // CHECK-NEXT: END TEST

  TEST(bp = new Base[2];) // CHECK: TEST
  // CHECK-NEXT: Base Constructor{{$}}
  // CHECK-NEXT: Base Constructor{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<Base*, L>(Base*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(delete[] bp;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<Base*, L>' -> 'Base* &'
  // CHECK-NEXT: Base Destructor{{$}}
  // CHECK-NEXT: Base Destructor{{$}}
  // CHECK-NEXT: END TEST

  TEST(iph = new int;) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, H>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(delete iph;) // CHECK: TEST
  // CHECK-NEXT: Implicit pointer decay: 'SE<int*, L, H>' -> 'SE<int, H>*'
  // CHECK-NEXT: END TEST

  TEST(iph = new int[2];) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int*, L, H>(int*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(delete[] iph;) // CHECK: TEST
  // CHECK-NEXT: Implicit pointer decay: 'SE<int*, L, H>' -> 'SE<int, H>*'
  // CHECK-NEXT: END TEST

  TEST(iph = new SE<int, H>[2];) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (canonicalize pointer): 'SE<int*, L, H>(SE<int, H>*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(delete[] iph;) // CHECK: TEST
  // CHECK-NEXT: Implicit pointer decay: 'SE<int*, L, H>' -> 'SE<int, H>*'
  // CHECK-NEXT: END TEST

  TEST(ipl = new SE<int, L>[2];) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (canonicalize pointer): 'SE<int*, L, L>(SE<int, L>*)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(delete[] ipl;) // CHECK: TEST
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int*, L, L>' -> 'int* &'
  // CHECK-NEXT: END TEST
}
