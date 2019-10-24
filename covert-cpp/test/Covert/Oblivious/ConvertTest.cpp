// RUN: %clang-llvmo -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %llio %t.bc | %FileCheck %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/ovector.h"

#undef NDEBUG
#include <cassert>

// expected-no-diagnostics

using namespace oblivious;
using namespace covert::__covert_logging__;

using HVector = ovector<SE<int, H>>;
using HVectorIt = typename HVector::iterator;
using HVectorConstIt = typename HVector::const_iterator;
COVERT_LOG_TYPE(HVector);
COVERT_LOG_TYPE(HVectorIt);
COVERT_LOG_TYPE(HVectorConstIt);

using LVector = ovector<SE<int, L>>;
using LVectorIt = typename LVector::iterator;
using LVectorConstIt = typename LVector::const_iterator;
COVERT_LOG_TYPE(LVector);
COVERT_LOG_TYPE(LVectorIt);
COVERT_LOG_TYPE(LVectorConstIt);

HVector hv{0, 1, 2, 3, 4, 5, 6, 7};
LVector lv{0, 1, 2, 3, 4, 5, 6, 7};

int main() {
  SE<O<HVectorIt, HVector>, H> phv{hv.begin(), &hv};
  SE<O<LVectorIt, LVector>, L> plv{lv.begin(), &lv};
  SE<O<LVectorConstIt, LVector>, L> cplv{lv.begin(), &lv};

  logd = &std::cout;

  TEST(SE<O<HVectorConstIt, HVector>, H> cphv = phv;); // CHECK: TEST
  // CHECK-NEXT: O Converting constructor: 'SE<O<HVectorConstIt, HVector>, H>(SE<O<HVectorIt, HVector>, H>)'
  // CHECK-NEXT: END TEST

  TEST(SE<O<LVectorConstIt, LVector>, L> cplv = plv;); // CHECK: TEST
  // CHECK-NEXT: O Converting constructor: 'SE<O<LVectorConstIt, LVector>, L>(SE<O<LVectorIt, LVector>, L>)'
  // CHECK-NEXT: END TEST

  TEST(SE<O<LVectorConstIt, LVector>, H> hcplv = cplv;); // CHECK: TEST
  // CHECK-NEXT: O Converting constructor: 'SE<O<LVectorConstIt, LVector>, H>(SE<O<LVectorConstIt, LVector>, L>)'
  // CHECK-NEXT: END TEST

  TEST(SE<O<LVectorConstIt, LVector>, H> cplv = plv;); // CHECK: TEST
  // CHECK-NEXT: O Converting constructor: 'SE<O<LVectorConstIt, LVector>, H>(SE<O<LVectorIt, LVector>, L>)'
  // CHECK-NEXT: END TEST

}
