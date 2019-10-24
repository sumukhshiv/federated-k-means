// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<int, H> a;
SE<int *, L, H> p;
SE<SE<int, H> *, H> nonp;

int main() {
  auto b = se_label_cast<int *, L, H>(a); // expected-error {{no matching function for call to 'se_label_cast'}}
  auto q = se_label_cast<int, L>(p); // expected-error {{no matching function for call to 'se_label_cast'}}
  auto r = se_label_cast<int, L>(nonp); // expected-error {{no matching function for call to 'se_label_cast'}}
}
