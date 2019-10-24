// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


struct Base {};

SE<Base *, H> bp;
SE<int *, H, H> iph;

int main() {
  delete bp; // expected-error {{cannot delete expression of type 'SE<Base *, H>'}}
  delete iph; // expected-error {{cannot delete expression of type 'SE<int *, H, H>'}}
}
