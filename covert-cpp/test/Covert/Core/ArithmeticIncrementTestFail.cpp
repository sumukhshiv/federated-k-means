// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<int, H> h = 2;
SE<int, L> arr[2];
const SE<int *, L, L> cp = nullptr;

int main() {
  SE<bool, L> nh = !h; // expected-error {{no viable conversion}}
  arr++; // expected-error {{cannot increment value of type 'SE<int, L> [2]'}}
  --arr; // expected-error {{cannot decrement value of type 'SE<int, L> [2]'}}
  ++cp; // expected-error {{cannot increment value of type 'const SE<int *, L, L>'}}
  cp--; // expected-error {{cannot decrement value of type 'const SE<int *, L, L>'}}
}
