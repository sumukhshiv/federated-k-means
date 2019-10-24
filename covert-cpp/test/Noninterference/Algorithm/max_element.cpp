// RUN: not %nvt -s 256 -- DynLoader %r/Algorithm/%basename.out | FileCheck %s

#ifdef __TEST__
#include <iostream>
#endif
#include <NVT.h>
#include <cov_algorithm.h>
#include <SE.h>
#include <algorithm>
#include "oforward_list.h"

#undef NDEBUG
#include <cassert>

NVT_TEST_MODULE;

using HList = oblivious::oforward_list<SE<int, H>>;
HList hl(256);
SE<oblivious::O<typename HList::iterator, HList>, H> hret;

using LList = oblivious::oforward_list<SE<int, L>>;
LList ll(256);
SE<oblivious::O<typename LList::iterator, LList>, L> lret;

extern "C" {

// CHECK-NOT: Test 1 failed
NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  assert(size == 256);
  std::for_each(hl.begin(), hl.end(), [&data](auto &x) { x = *data++; });
}

NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  hret = covert::max_element(hl.begin(), hl.end(), &hl);
}

// CHECK: Test 2 failed
NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data, unsigned size) {
  assert(size == 256);
  std::for_each(ll.begin(), ll.end(), [&data](auto &x) { x = *data++; });
}

NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  lret = covert::max_element(ll.begin(), ll.end(), &ll);
}
}
