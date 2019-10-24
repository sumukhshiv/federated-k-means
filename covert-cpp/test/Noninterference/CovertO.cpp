// RUN: not %nvt -s 2 -- DynLoader %r/%basename.out | FileCheck %s

#include "NVT.h"
#include "SE.h"
#include "CovertO.h"
#include "ovector.h"
#include "olist.h"
#include <cassert>

NVT_TEST_MODULE;

using namespace oblivious;

using HVector = ovector<SE<int, H>>;
using HVectorIt = typename HVector::iterator;
using HList = olist<SE<int, H>>;
using HListIt = typename HList::iterator;

HVector hv(256);
SE<O<HVectorIt, HVector>, H> hviter {hv.begin(), &hv};
HList hl(256);
SE<O<HListIt, HList>, H> hliter {hl.begin(), &hl};
SE<O<HListIt, HList>, H> _hliter {hl.begin(), &hl};

using LVector = ovector<SE<int, L>>;
using LVectorIt = typename LVector::iterator;
using LList = olist<SE<int, L>>;
using LListIt = typename LList::iterator;

LVector lv(256);
SE<O<LVectorIt, LVector>, L> lviter {lv.begin(), &lv};
LList ll(256);
SE<O<LListIt, LList>, L> lliter {ll.begin(), &ll};
SE<O<LListIt, LList>, L> _lliter {ll.begin(), &ll};

int idx, val;
SE<int, H> ret;

extern "C" {

NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  assert(size >= 2);
  idx = data[0];
  val = data[1];
}

// CHECK-NOT: Test 1 failed
NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  ret = hviter[idx];
  hviter[idx] = ret;
}

NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data, unsigned size) {
  assert(size >= 2);
  idx = data[0];
  val = data[1];
  _hliter = hliter;
  for (int i = 0; i < idx; ++i) {
    ++_hliter;
  }
}

// CHECK-NOT: Test 2 failed
NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  ret = *_hliter;
  *_hliter = ret;
}

NVT_EXPORT void NVT_TEST_INIT(3)(unsigned char *data, unsigned size) {
  assert(size >= 2);
  idx = data[0];
  val = data[1];
}

// CHECK: Test 3 failed
NVT_EXPORT void NVT_TEST_BEGIN(3)(void) {
  ret = lviter[idx];
  lviter[idx] = val;
}

NVT_EXPORT void NVT_TEST_INIT(4)(unsigned char *data, unsigned size) {
  assert(size >= 2);
  idx = data[0];
  val = data[1];
  _lliter = lliter;
  for (int i = 0; i < idx; ++i) {
    ++_lliter;
  }
}

// CHECK: Test 4 failed
NVT_EXPORT void NVT_TEST_BEGIN(4)(void) {
  ret = *_lliter;
  *_lliter = val;
}
}
