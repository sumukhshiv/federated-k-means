// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<long, H> l = 2;
SE<int, L> a = 2;
const SE<int, L> cx = 2;
SE<int, L> x = 2;
SE<int *, L, L> p;
SE<int, L> arr[2];

int main() {
  cx += 2; // expected-error {{no viable overloaded '+='}}
  x += nullptr; // expected-error {{no viable overloaded '+='}}
  p += p; // expected-error {{no viable overloaded '+='}}
  p *= 2; // expected-error {{no viable overloaded '*='}}
  arr += 2; // expected-error {{invalid operands to binary expression}}
  a += l; // expected-error {{no viable overloaded '+='}}
}
