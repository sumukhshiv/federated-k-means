// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

class C1 {
  int _x;
public:
  C1(int x) : _x(x) {}
};

class C2 {
  int _x;
  double _y;
public:
  C2(int x, double y) : _x(x), _y(y) {}
};

struct S1 {
  int x;
};

struct S2 {
  int x;
  double y;
};

COVERT_LOG_TYPE(C1);
COVERT_LOG_TYPE(C2);
COVERT_LOG_TYPE(S1);
COVERT_LOG_TYPE(S2);

namespace covert {
template <> struct type_depth<C1> : std::integral_constant<unsigned, 1> {};
template <> struct type_depth<C2> : std::integral_constant<unsigned, 1> {};
template <> struct type_depth<S1> : std::integral_constant<unsigned, 1> {};
template <> struct type_depth<S2> : std::integral_constant<unsigned, 1> {};
} // end namespace covert

int main() {
  logd = &std::cout;

  TEST(SE<C1, L> c{{12}};) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<C1, L>(C1)'
  // CHECK-NEXT: END TEST

  TEST(SE<C2, L> c{{12, 1.0}};) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<C2, L>(C2)'
  // CHECK-NEXT: END TEST

  TEST(SE<S1, L> s{{12}};) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<S1, L>(S1)'
  // CHECK-NEXT: END TEST

  TEST(SE<S2, L> s{{12, 1.0}};) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<S2, L>(S2)'
  // CHECK-NEXT: END TEST
}
