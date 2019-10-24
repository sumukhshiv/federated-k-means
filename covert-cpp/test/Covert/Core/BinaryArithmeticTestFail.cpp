// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


int _x, *_p;
SE<long, H> l = 2;
SE<int, L> a = 2;
SE<int *, L, L> p;

int main() {
  auto r1 = p + p; // expected-error {{invalid operands to binary expression}}
  auto r2 = p + _p; // expected-error {{invalid operands to binary expression}}
  SE<long, L> r3 = l + a; // expected-error {{no viable conversion}}
  auto r4 = a << p; // expected-error {{invalid operands to binary expression}}
}
