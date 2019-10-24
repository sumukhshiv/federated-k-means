// RUN: %clang-syntaxo -Xclang -verify %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/ovector.h"
#include "Oblivious/olist.h"

using namespace oblivious;

using LNCVector = ovector<int>;
using LNCVectorIt = typename LNCVector::iterator;
using LNCVectorConstIt = typename LNCVector::const_iterator;

using LVector = ovector<SE<int, L>>;
using LVectorIt = typename LVector::iterator;
using LVectorConstIt = typename LVector::const_iterator;

using HVector = ovector<SE<int, H>>;
using HVectorIt = typename HVector::iterator;
using HVectorConstIt = typename HVector::const_iterator;

LVector lv;
LNCVector lncv;
HVector hv;

int main() {
  // expected-error@Covert/__covert_o_impl.h:* {{IterT must either be the const or non-const iterator for ContainerT}}
  { SE<O<int *, LVector>, L> plv{lv.begin(), &lv}; } // expected-note-re {{in instantiation of template class '{{.+}}' requested here}}
  // expected-error@Covert/__covert_o_impl.h:* {{IterT must either be the const or non-const iterator for ContainerT}}
  { SE<O<const int *, LVector>, L> cplv{lv.cbegin(), &lv}; } // expected-note-re {{in instantiation of template class '{{.+}}' requested here}}

  // expected-error@Covert/__covert_o_impl.h:* {{IterT's value_type must be in canonical form}}
  { SE<O<LNCVectorIt, LNCVector>, L> plv{lncv.begin(), &lncv}; } // expected-note-re {{in instantiation of template class '{{.+}}' requested here}}
  // expected-error@Covert/__covert_o_impl.h:* {{IterT's value_type must be in canonical form}}
  { SE<O<LNCVectorConstIt, LNCVector>, L> cplv{lncv.cbegin(), &lncv}; } // expected-note-re {{in instantiation of template class '{{.+}}' requested here}}

  { SE<O<LVectorIt, LVector>, H> plv{lv.begin(), &lv}; } // expected-no-error
  { SE<O<LVectorIt, LVector>, L> plv{lv.begin(), &lv}; } // expected-no-error
}
