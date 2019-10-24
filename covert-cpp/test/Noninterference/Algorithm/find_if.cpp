// RUN: not %nvt -s 9 -- DynLoader %r/Algorithm/%basename.out | FileCheck %s

#ifdef __TEST__
#include <iostream>
#endif
#include <NVT.h>
#include "cov_algorithm.h"
#include "SE.h"
#include <forward_list>
#include <algorithm>

NVT_TEST_MODULE;

///////
// Test Forward List

using HFwdList = std::forward_list<SE<uint8_t, H>>;
template <SLabel S> using HFwdIt = SE<HFwdList::iterator, S>;

namespace covert {
template <>
struct type_depth<HFwdList::iterator> : std::integral_constant<unsigned, 1> {};
} // namespace covert

static HFwdList hfl(8);
static SE<uint8_t, H> hlt;
HFwdIt<H> hret;

using LFwdList = std::forward_list<SE<uint8_t, L>>;
template <SLabel S> using LFwdIt = SE<LFwdList::iterator, S>;

namespace covert {
template <>
struct type_depth<LFwdList::iterator> : std::integral_constant<unsigned, 1> {};
} // namespace covert

static LFwdList lfl(8);
static SE<uint8_t, L> llt;
LFwdIt<L> lret;

extern "C" {

NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  hlt = *data++;
  std::for_each(hfl.begin(), hfl.end(), [&data](auto &x) { x = *data++; });
}

// CHECK-NOT: Test 1 failed
NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  HFwdIt<L> I = hfl.begin();
  HFwdIt<L> E = hfl.end();
  hret = covert::find_if(I, E, [](auto v) { return v < hlt; });
#ifdef __TEST__
  if (se_label_cast<bool, L>(hret != E)) {
    auto R = se_label_cast<HFwdList::iterator, L>(hret);
    auto V = se_label_cast<uint8_t, L>(*R);
    std::cout << "Found '" << V << "' < '" << se_to_primitive(hlt)
              << "' at index " << se_to_primitive(std::distance(I, R)) << "\n";
  } else {
    std::cout << "Could not find < '" << se_to_primitive(hlt) << "'\n";
  }
#endif
}

NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data, unsigned size) {
  llt = *data++;
  std::for_each(lfl.begin(), lfl.end(), [&data](auto &x) { x = *data++; });
}

// CHECK: Test 2 failed
NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  LFwdIt<L> I = lfl.begin();
  LFwdIt<L> E = lfl.end();
  lret = covert::find_if(I, E, [](auto v) { return v < llt; });
}
}

#ifdef __TEST__
int main() {
  unsigned char data[] = {2, 3, 6, 2, 4};
  NVT_TEST_INIT(1)(data, sizeof(data));
  NVT_TEST_BEGIN(1)();
  hlt = 3;
  NVT_TEST_BEGIN(1)();
  hlt = 5;
  NVT_TEST_BEGIN(1)();
}
#endif
