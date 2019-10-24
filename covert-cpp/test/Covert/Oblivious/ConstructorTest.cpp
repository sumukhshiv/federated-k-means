// RUN: %clang-llvmo -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %llio %t.bc | %FileCheck %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/ovector.h"
#include "Oblivious/olist.h"

// expected-no-diagnostics

using namespace oblivious;
using namespace covert::__covert_logging__;

using LVector = ovector<SE<int, L>>;
using LVectorIt = typename LVector::iterator;
using LVectorConstIt = typename LVector::const_iterator;
COVERT_LOG_TYPE(LVector);
COVERT_LOG_TYPE(LVectorIt);
COVERT_LOG_TYPE(LVectorConstIt);

using HVector = ovector<SE<int, H>>;
using HVectorIt = typename HVector::iterator;
using HVectorConstIt = typename HVector::const_iterator;
COVERT_LOG_TYPE(HVector);
COVERT_LOG_TYPE(HVectorIt);
COVERT_LOG_TYPE(HVectorConstIt);

LVector lv{0, 1, 2, 3, 4, 5, 6, 7};
HVector hv{0, 1, 2, 3, 4, 5, 6, 7};

int main() {
  logd = &std::cout;

  TEST(SE<O<HVectorIt, HVector>, H> phv{{hv.begin(), &hv}};) // CHECK: TEST
  // CHECK-NEXT: O Converting constructor (primitive): 'SE<O<HVectorIt, HVector>, H>(O<HVectorIt, HVector>)'
  // CHECK-NEXT: END TEST

  TEST(SE<O<HVectorIt, HVector>, H> phv{hv.begin(), &hv};) // CHECK: TEST
  // CHECK-NEXT: O constructor: 'SE<O<HVectorIt, HVector>, H>(O<HVectorIt, HVector>)'
  // CHECK-NEXT: END TEST
  TEST(SE<O<HVectorConstIt, HVector>, H> cphv{hv.begin(), &hv};) // CHECK: TEST
  // CHECK-NEXT: O constructor: 'SE<O<HVectorConstIt, HVector>, H>(O<HVectorConstIt, HVector>)'
  // CHECK-NEXT: END TEST

  TEST(SE<O<LVectorIt, LVector>, L> plv{lv.begin(), &lv};) // CHECK: TEST
  // CHECK-NEXT: O constructor: 'SE<O<LVectorIt, LVector>, L>(O<LVectorIt, LVector>)'
  // CHECK-NEXT: END TEST
  TEST(SE<O<LVectorIt, LVector>, H> hplv{lv.begin(), &lv};) // CHECK: TEST
  // CHECK-NEXT: O constructor: 'SE<O<LVectorIt, LVector>, H>(O<LVectorIt, LVector>)'
  // CHECK-NEXT: END TEST
  TEST(SE<O<LVectorConstIt, LVector>, L> cplv{lv.begin(), &lv};) // CHECK: TEST
  // CHECK-NEXT: O constructor: 'SE<O<LVectorConstIt, LVector>, L>(O<LVectorConstIt, LVector>)'
  // CHECK-NEXT: END TEST
  TEST(SE<O<LVectorConstIt, LVector>, H> hcplv{lv.begin(), &lv};) // CHECK: TEST
  // CHECK-NEXT: O constructor: 'SE<O<LVectorConstIt, LVector>, H>(O<LVectorConstIt, LVector>)'
  // CHECK-NEXT: END TEST
}
