// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


int x;
SE<void *, L> vp;
SE<int *, L, H> iph;
SE<int *, H, L> iph2;

void foo() {
  { SE<void *, L> r = iph; } // expected-error {{no viable conversion}}
  { SE<int *, L, L> r = iph; } // expected-error {{no viable conversion}}
  { SE<int *, L, L> r = vp; } // expected-error {{no viable conversion}}
  { SE<int *, L, L> r = iph2; } // expected-error {{no viable conversion}}
  { SE<char *, L, L> r = iph2; } // expected-error {{no viable conversion}}
  { SE<int *, L, L> p = x; } // expected-error {{no viable conversion}}
}
