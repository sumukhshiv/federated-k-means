// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<int, L> *_pl;
const SE<int, L> *_cpl;
SE<int, H> *_ph;
SE<SE<int, H> *, L> *_pph;

void foo() {
  { SE<char *, L, L> r = _pl; } // expected-error {{no viable conversion}}
  { SE<int *, L, L> r = _cpl; } // expected-error {{no viable conversion}}
  { SE<int *, L, L> r = _ph; } // expected-error {{no viable conversion}}
  { SE<int **, L, L, L> r = _pph; } // expected-error {{no viable conversion}}
}
