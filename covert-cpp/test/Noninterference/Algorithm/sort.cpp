// RUN: not %nvt -s 32 -- DynLoader %r/Algorithm/%basename.out | FileCheck %s

#ifdef __TEST__
#include <iostream>
#endif
#include <NVT.h>
#include <cov_algorithm.h>
#include <SE.h>
#include <algorithm>
#include "ovector.h"

#undef NDEBUG
#include <cassert>

NVT_TEST_MODULE;

using HVector = oblivious::ovector<SE<int, H>>;
HVector hv(32);

using LVector = oblivious::ovector<SE<int, L>>;
LVector lv(32);

extern "C" {

// CHECK-NOT: Test 1 failed
NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  assert(size == 32);
  std::for_each(hv.begin(), hv.end(), [&data](auto &x) { x = *data++; });
}

NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  covert::sort(hv.begin(), hv.end());
}

// CHECK: Test 2 failed
NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data, unsigned size) {
  assert(size == 32);
  std::for_each(lv.begin(), lv.end(), [&data](auto &x) { x = *data++; });
}

NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  covert::sort(lv.begin(), lv.end());
}
}
