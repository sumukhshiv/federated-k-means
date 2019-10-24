// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<long, H> l = 2;
SE<int, L> a = 2;
int x;
SE<double, L> d = 2;
SE<int *, L, L> p;

int main() {
  SE<bool, L> ra = a < l; // expected-error {{no viable conversion}}
  SE<bool, L> r = a == p; // expected-error {{invalid operands to binary expression}}
  SE<bool, L> r2 = x == p; // expected-error {{invalid operands to binary expression}}
}
