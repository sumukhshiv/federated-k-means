// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<int, H> h = 2;
SE<int *, L, L> p;

int main() {
  -p; // expected-error {{invalid argument type}}
  ~p; // expected-error {{invalid argument type}}
  SE<bool, L> nh = ~h; // expected-error {{no viable conversion}}
}
