// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include <cstdint>
#include <Covert/SE.h>

// expected-no-diagnostics

using namespace covert::__covert_logging__;

struct A {};
struct B {};
COVERT_LOG_TYPE(A);
COVERT_LOG_TYPE(B);

SE<A *, H> ap;
SE<int, L> x;
SE<int *, L, L> ip;
SE<void **, L, L> vpp;
SE<int, H> *nhp;

int main() {
  logd = &std::cout;

  // 1: convert to self
  TEST(se_reinterpret_cast<int, L>(x);) // CHECK: TEST
  // CHECK-NEXT: se_reinterpret_cast: 'SE<int, L> &' -> 'SE<int, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'{{$}}
  // CHECK-NEXT: END TEST

  // 2: convert to type large enough to hold pointer
  TEST(se_reinterpret_cast<intptr_t, L>(ip);) // CHECK: TEST
  // CHECK-NEXT: se_reinterpret_cast: 'SE<int*, L, L> &' -> 'SE<long, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<long, L>(long)'{{$}}
  // CHECK-NEXT: END TEST

  // 3: convert integral type to pointer
  TEST(se_reinterpret_cast<void *, L>(x);) // CHECK: TEST
  // CHECK-NEXT: se_reinterpret_cast: 'SE<int, L> &' -> 'SE<void*, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<void*, L>(void*)'{{$}}
  // CHECK-NEXT: END TEST

  // 5: convert between pointer-to-object types
  TEST(se_reinterpret_cast<B *, H>(ap);) // CHECK: TEST
  // CHECK-NEXT: se_reinterpret_cast: 'SE<A*, H> &' -> 'SE<B*, H>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<B*, H>(B*)'{{$}}
  // CHECK-NEXT: END TEST

  // 6a: lvalue to lvalue reference to different type
  TEST(SE<short, L> &r = se_reinterpret_cast<short &, L>(x);) // CHECK: TEST
  // CHECK-NEXT: se_reinterpret_cast: 'SE<int, L> &' -> 'SE<short, L> &'{{$}}
  // CHECK-NEXT: END TEST

  // 6a: lvalue to xvalue
  TEST(se_reinterpret_cast<short &&, L>(x);) // CHECK: TEST
  // CHECK-NEXT: se_reinterpret_cast: 'SE<int, L> &' -> 'SE<short, L> &&'{{$}}
  // CHECK-NEXT: END TEST

  // non-canonical argument
  TEST(se_reinterpret_cast<int *&, L, H>(nhp);) // CHECK: TEST
  // CHECK-NEXT: se_reinterpret_cast: 'SE<int, H>* &' -> 'SE<int*, L, H> &'{{$}}
  // CHECK-NEXT: END TEST
}
