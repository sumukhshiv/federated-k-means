// RUN: %clang-syntaxo -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/ovector.h"

#undef NDEBUG
#include <cassert>

using namespace oblivious;

using HVector = ovector<SE<int, H>>;
using HVectorIt = typename HVector::iterator;
using HVectorConstIt = typename HVector::const_iterator;
using LVector = ovector<SE<int, L>>;
using LVectorIt = typename LVector::iterator;
using LVectorConstIt = typename LVector::const_iterator;

HVector hv{0, 1, 2, 3, 4, 5, 6, 7};
LVector lv{0, 1, 2, 3, 4, 5, 6, 7};

int main() {
  SE<O<HVectorIt, HVector>, H> hphv{hv.begin(), &hv};
  SE<O<LVectorIt, LVector>, L> lplv{lv.begin(), &lv};
  SE<O<HVectorConstIt, HVector>, H> hcphv{hv.cbegin(), &hv};
  SE<O<LVectorConstIt, LVector>, L> lcplv{lv.cbegin(), &lv};

  {SE<O<HVectorIt, HVector>, L> lphv = hphv;} // expected-error {{no viable conversion}}
  {SE<O<HVectorIt, HVector>, H> hphv = hcphv;} // expected-error {{no viable conversion}}
  {SE<O<LVectorIt, LVector>, H> hplv = lplv;} // expected-no-error
  {SE<O<LVectorConstIt, LVector>, H> hcplv = lcplv;} // expected-no-error
}
