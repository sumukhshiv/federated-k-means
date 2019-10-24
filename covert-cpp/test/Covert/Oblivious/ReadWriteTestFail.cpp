// RUN: %clang-syntaxo -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/ovector.h"
#include "Oblivious/olist.h"

using namespace oblivious;

using LList = olist<SE<int, L>>;
using LListIt = typename LList::iterator;
using LListConstIt = typename LList::const_iterator;
using LVector = ovector<SE<int, L>>;
using LVectorIt = typename LVector::iterator;
using LVectorConstIt = typename LVector::const_iterator;
using HList = olist<SE<int, H>>;
using HListIt = typename HList::iterator;
using HListConstIt = typename HList::const_iterator;
using HVector = ovector<SE<int, H>>;
using HVectorIt = typename HVector::iterator;
using HVectorConstIt = typename HVector::const_iterator;

LList ll;
LVector lv;
HList hl;
HVector hv;

SE<std::size_t, H> hidx = 0;
SE<std::size_t, L> lidx = 0;

int main() {
  SE<O<HListIt, HList>, H> phl{hl.begin(), &hl};
  SE<O<HListConstIt, HList>, H> cphl{hl.begin(), &hl};
  SE<O<HVectorIt, HVector>, H> phv{hv.begin(), &hv};
  SE<O<HVectorConstIt, HVector>, H> cphv{hv.begin(), &hv};

  SE<O<LListIt, LList>, L> pll{ll.begin(), &ll};
  SE<O<LListConstIt, LList>, L> cpll{ll.begin(), &ll};
  SE<O<LVectorIt, LVector>, L> plv{lv.begin(), &lv};
  SE<O<LVectorConstIt, LVector>, L> cplv{lv.begin(), &lv};

  *cphl = 42; // expected-error {{no viable overloaded '='}}
  SE<int, H> x = phl[0]; // expected-error {{no viable overloaded operator[]}}
  int li = *phl; // expected-error {{no viable conversion}}
  phl[0] = 42; // expected-error {{no viable overloaded operator[]}}
  *cphv = 42; // expected-error {{no viable overloaded '='}}
  int vi = *phv; // expected-error {{no viable conversion}}
  cphv[0] = 42; // expected-error {{no viable overloaded '='}}

  *cpll = 42; // expected-error {{no viable overloaded '='}}
  SE<int, L> _x = pll[0]; // expected-error {{no viable overloaded operator[]}}
  pll[0] = 42; // expected-error {{no viable overloaded operator[]}}
  *cplv = 42; // expected-error {{no viable overloaded '='}}
  cplv[0] = 42; // expected-error {{no viable overloaded '='}}
  {SE<int, L> val = plv[hidx];} // expected-error {{no viable conversion}}
  {SE<int, L> val = plv[lidx];} // expected-no-error
  {plv[hidx] = 42;} // expected-error {{no viable overloaded '='}}
  {plv[lidx] = 42;} // expected-no-error
}
