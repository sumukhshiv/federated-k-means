// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<int *, L, L> p;
SE<int *, H, L> hp;

int main() {
  // mismatched SLevel
  { SE<int, L> *_p = hp; } // expected-error {{no viable conversion}}
  // different type
  { SE<char, L> *_p = p; } // expected-error {{no viable conversion}}
  // different type
  { SE<char, L> **_p = p; } // expected-error {{no viable conversion}}

  { SE<SE<char, L> *, L> _p = p; } // expected-error {{no viable conversion}}
}
