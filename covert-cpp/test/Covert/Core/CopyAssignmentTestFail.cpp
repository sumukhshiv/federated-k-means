// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


const SE<int, L> cx = 2;
SE<int, L> x = 2;
SE<int *, L, L> p;
SE<void *, L> vp;

int main() {
  p = x; // expected-error {{no viable overloaded '='}}
  cx = cx; // expected-error {{no viable overloaded '='}}
  p = vp; // expected-error {{no viable overloaded '='}}
}
