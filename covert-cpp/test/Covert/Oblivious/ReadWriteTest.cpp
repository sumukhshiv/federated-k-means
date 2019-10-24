// RUN: %clang-llvmo -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %llio %t.bc | %FileCheck %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/ovector.h"
#include "Oblivious/olist.h"

// expected-no-diagnostics

using namespace oblivious;
using namespace covert::__covert_logging__;

using LList = olist<SE<int, L>>;
using LListIt = typename LList::iterator;
using LListConstIt = typename LList::const_iterator;
COVERT_LOG_TYPE(LList);
COVERT_LOG_TYPE(LListIt);
COVERT_LOG_TYPE(LListConstIt);

using LVector = ovector<SE<int, L>>;
using LVectorIt = typename LVector::iterator;
using LVectorConstIt = typename LVector::const_iterator;
COVERT_LOG_TYPE(LVector);
COVERT_LOG_TYPE(LVectorIt);
COVERT_LOG_TYPE(LVectorConstIt);

using HList = olist<SE<int, H>>;
using HListIt = typename HList::iterator;
using HListConstIt = typename HList::const_iterator;
COVERT_LOG_TYPE(HList);
COVERT_LOG_TYPE(HListIt);
COVERT_LOG_TYPE(HListConstIt);

using HVector = ovector<SE<int, H>>;
using HVectorIt = typename HVector::iterator;
using HVectorConstIt = typename HVector::const_iterator;
COVERT_LOG_TYPE(HVector);
COVERT_LOG_TYPE(HVectorIt);
COVERT_LOG_TYPE(HVectorConstIt);

LList ll{0, 1, 2, 3, 4, 5, 6, 7};
LVector lv{0, 1, 2, 3, 4, 5, 6, 7};
HList hl{0, 1, 2, 3, 4, 5, 6, 7};
HVector hv{0, 1, 2, 3, 4, 5, 6, 7};

SE<std::size_t, H> hidx = 0;
SE<std::size_t, L> lidx = 0;

int main() {
  SE<O<HListIt, HList>, H> hphl{hl.begin(), &hl};
  SE<O<HListConstIt, HList>, H> hcphl{hl.begin(), &hl};
  SE<O<HVectorIt, HVector>, H> hphv{hv.begin(), &hv};
  SE<O<HVectorConstIt, HVector>, H> hcphv{hv.begin(), &hv};

  SE<O<LListIt, LList>, L> lpll{ll.begin(), &ll};
  SE<O<LListConstIt, LList>, L> lcpll{ll.begin(), &ll};
  SE<O<LListConstIt, LList>, H> hcpll{ll.begin(), &ll};
  SE<O<LVectorIt, LVector>, L> lplv{lv.begin(), &lv};
  SE<O<LVectorConstIt, LVector>, L> lcplv{lv.begin(), &lv};
  SE<O<LVectorConstIt, LVector>, H> hcplv{lv.begin(), &lv};

  logd = &std::cout;

  TEST(typename decltype(*hphl)::value_type x = *hphl;); // CHECK: TEST
  // CHECK-NEXT: SE<O<HListIt, HList>, H>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious read: 'SE<int, H>' -> 'SE<int, H>'
  // CHECK-NEXT: END TEST

  TEST(*hphl = 42;); // CHECK: TEST
  // CHECK-NEXT: SE<O<HListIt, HList>, H>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious write: 'int' -> 'SE<int, H>'
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, H>(int)'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(*hcphl)::value_type x = *hcphl;); // CHECK: TEST
  // CHECK-NEXT: SE<O<HListConstIt, HList>, H>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious read: 'SE<int, H>' -> 'SE<int, H>'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(*hphv)::value_type x = *hphv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<HVectorIt, HVector>, H>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious read: 'SE<int, H>' -> 'SE<int, H>'
  // CHECK-NEXT: END TEST

  TEST(*hphv = 42;); // CHECK: TEST
  // CHECK-NEXT: SE<O<HVectorIt, HVector>, H>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious write: 'int' -> 'SE<int, H>'
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, H>(int)'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(*hcphv)::value_type x = *hcphv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<HVectorConstIt, HVector>, H>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious read: 'SE<int, H>' -> 'SE<int, H>'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(hphv[0])::value_type x = hphv[0];); // CHECK: TEST
  // CHECK-NEXT: SE<O<HVectorIt, HVector>, H>, int: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious read: 'SE<int, H>' -> 'SE<int, H>'
  // CHECK-NEXT: END TEST

  TEST(hphv[0] = 42;); // CHECK: TEST
  // CHECK-NEXT: SE<O<HVectorIt, HVector>, H>, int: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious write: 'int' -> 'SE<int, H>'
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, H>(int)'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(hcphv[0])::value_type x = hcphv[0];); // CHECK: TEST
  // CHECK-NEXT: SE<O<HVectorConstIt, HVector>, H>, int: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious read: 'SE<int, H>' -> 'SE<int, H>'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(*lpll)::value_type x = *lpll;); // CHECK: TEST
  // CHECK-NEXT: SE<O<LListIt, LList>, L>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'SE<int, L>'
  // CHECK-NEXT: END TEST

  TEST(*lpll = 42;); // CHECK: TEST
  // CHECK-NEXT: SE<O<LListIt, LList>, L>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious write: 'int' -> 'SE<int, L>'
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(*lcpll)::value_type x = *lcpll;); // CHECK: TEST
  // CHECK-NEXT: SE<O<LListConstIt, LList>, L>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'SE<int, L>'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(*hcpll)::value_type x = *hcpll;); // CHECK: TEST
  // CHECK-NEXT: SE<O<LListConstIt, LList>, H>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'SE<int, H>'
  // CHECK-NEXT: Converting constructor (Covert): 'SE<int, H>(SE<int, L>)'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(*lplv)::value_type x = *lplv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorIt, LVector>, L>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'SE<int, L>'
  // CHECK-NEXT: END TEST

  TEST(*lplv = 42;); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorIt, LVector>, L>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious write: 'int' -> 'SE<int, L>'
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(*lcplv)::value_type x = *lcplv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorConstIt, LVector>, L>: Oblivious iterator dereference operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'SE<int, L>'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(lplv[0])::value_type x = lplv[0];); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorIt, LVector>, L>, int: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'SE<int, L>'
  // CHECK-NEXT: END TEST

  TEST(lplv[0] = 42;); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorIt, LVector>, L>, int: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious write: 'int' -> 'SE<int, L>'
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, L>(int)'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(lcplv[0])::value_type x = lcplv[0];); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorConstIt, LVector>, L>, int: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'SE<int, L>'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(lcplv[0])::value_type x = lcplv[0];); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorConstIt, LVector>, L>, int: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'SE<int, L>'
  // CHECK-NEXT: END TEST

  TEST(typename decltype(lcplv[hidx])::value_type x = lcplv[hidx];); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorConstIt, LVector>, L>, SE<{{.+}}, H>: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'SE<int, H>'
  // CHECK-NEXT: Converting constructor (Covert): 'SE<int, H>(SE<int, L>)'
  // CHECK-NEXT: END TEST

  TEST(hphv[lidx] = 42;); // CHECK: TEST
  // CHECK-NEXT: SE<O<HVectorIt, HVector>, H>, SE<{{.+}}, L>: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious write: 'int' -> 'SE<int, H>'
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, H>(int)'
  // CHECK-NEXT: END TEST

  TEST(hphv[hidx] = 42;); // CHECK: TEST
  // CHECK-NEXT: SE<O<HVectorIt, HVector>, H>, SE<{{.+}}, H>: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious write: 'int' -> 'SE<int, H>'
  // CHECK-NEXT: Converting constructor (primitive): 'SE<int, H>(int)'
  // CHECK-NEXT: END TEST

  TEST(int x = lplv[lidx];); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorIt, LVector>, L>, SE<{{.+}}, L>: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'int'
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'
  // CHECK-NEXT: END TEST

  TEST(const int &x = lplv[lidx];); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorIt, LVector>, L>, SE<{{.+}}, L>: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'int'
  // CHECK-NEXT: Implicit primitive type conversion (reference): 'SE<int, L>' -> 'int &'
  // CHECK-NEXT: END TEST

  TEST(SE<int, H> x = lplv[lidx];); // CHECK: TEST
  // CHECK-NEXT: SE<O<LVectorIt, LVector>, L>, SE<{{.+}}, L>: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious read: 'SE<int, L>' -> 'SE<int, H>'
  // CHECK-NEXT: Converting constructor (Covert): 'SE<int, H>(SE<int, L>)'
  // CHECK-NEXT: END TEST

  SE<int, H> y = 42;
  TEST(SE<int, H> x = hphv[lidx] = y;); // CHECK: TEST
  // CHECK-NEXT: SE<O<HVectorIt, HVector>, H>, SE<{{.+}}, L>: Oblivious iterator subscript operator
  // CHECK-NEXT: Oblivious write: 'SE<int, H>' -> 'SE<int, H>'
  // CHECK-NEXT: Oblivious read: 'SE<int, H>' -> 'SE<int, H>'
  // CHECK-NEXT: END TEST

}
