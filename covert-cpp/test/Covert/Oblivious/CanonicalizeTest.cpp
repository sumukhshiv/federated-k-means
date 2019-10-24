// RUN: %clang-llvmo -fsyntax-only -Xclang -verify %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/ovector.h"

// expected-no-diagnostics

using namespace oblivious;
using namespace covert;
using namespace covert::__covert_impl__;

using LVector = ovector<SE<int, L>>;
using LVectorIt = typename LVector::iterator;
using LVectorConstIt = typename LVector::const_iterator;
using HVector = ovector<SE<int, H>>;
using HVectorIt = typename HVector::iterator;
using HVectorConstIt = typename HVector::const_iterator;

LVector lv;
HVector hv;

int main() {
  SE<O<LVectorIt, LVector>, L> lplv{lv.begin(), &lv};
  SE<O<LVectorIt, LVector>, H> hplv{lv.begin(), &lv};
  SE<O<LVectorConstIt, LVector>, L> lcplv{lv.begin(), &lv};
  SE<O<LVectorConstIt, LVector>, H> hcplv{lv.begin(), &lv};
  SE<O<HVectorIt, HVector>, L> lphv{hv.begin(), &hv};
  SE<O<HVectorIt, HVector>, H> hphv{hv.begin(), &hv};
  SE<O<HVectorConstIt, HVector>, L> lcphv{hv.begin(), &hv};
  SE<O<HVectorConstIt, HVector>, H> hcphv{hv.begin(), &hv};

  static_assert(std::is_same_v<canonicalize_t<SLabel, decltype(*lplv)>, SE<int, L>>);
  static_assert(std::is_same_v<canonicalize_t<SLabel, decltype(*hplv)>, SE<int, H>>);
  static_assert(std::is_same_v<canonicalize_t<SLabel, decltype(*lcplv)>, SE<int, L>>);
  static_assert(std::is_same_v<canonicalize_t<SLabel, decltype(*hcplv)>, SE<int, H>>);
  static_assert(std::is_same_v<canonicalize_t<SLabel, decltype(*lphv)>, SE<int, H>>);
  static_assert(std::is_same_v<canonicalize_t<SLabel, decltype(*hphv)>, SE<int, H>>);
  static_assert(std::is_same_v<canonicalize_t<SLabel, decltype(*lcphv)>, SE<int, H>>);
  static_assert(std::is_same_v<canonicalize_t<SLabel, decltype(*hcphv)>, SE<int, H>>);
}
