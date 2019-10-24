// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<int, H> h = 2;

int main() {
  SE<bool, L> nh = !h; // expected-error {{no viable conversion}}
}
