// RUN: %clang-llvmo -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %llio %t.bc | %FileCheck %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/ovector.h"
#include "Oblivious/olist.h"

// expected-no-diagnostics

using namespace oblivious;
using namespace covert::__covert_logging__;

using List = olist<SE<int, H>>;
using ListIt = typename List::iterator;
COVERT_LOG_TYPE(List);
COVERT_LOG_TYPE(ListIt);

using Vector = ovector<SE<int, H>>;
using VectorIt = typename Vector::iterator;
COVERT_LOG_TYPE(Vector);
COVERT_LOG_TYPE(VectorIt);

List l{0, 1, 2, 3, 4, 5, 6, 7};
Vector v{0, 1, 2, 3, 4, 5, 6, 7};

int main() {
  SE<O<ListIt, List>, H> pl{{l.begin(), &l}};
  SE<O<VectorIt, Vector>, H> pv{{v.begin(), &v}};

  logd = &std::cout;

  TEST(--pl;); // CHECK: TEST
  // CHECK-NEXT: SE<O<ListIt, List>, H>: operator-- (prefix)
  // CHECK-NEXT: END TEST

  TEST(pl--;); // CHECK: TEST
  // CHECK-NEXT: SE<O<ListIt, List>, H>: operator-- (postfix)
  // CHECK-NEXT: END TEST

  TEST(--pv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>: operator-- (prefix)
  // CHECK-NEXT: END TEST

  TEST(pv--;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>: operator-- (postfix)
  // CHECK-NEXT: END TEST

}
