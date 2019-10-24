// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<int, L> l;
SE<int, H> h;

int main() {
  auto cond = [](auto x) { if (x) {} };
  cond(l); // expected-no-note
  cond(h); // expected-error-re@-2 {{no viable conversion from '{{.+}}' to 'bool'}} expected-note-re {{in instantiation of function template specialization '{{.+}}' requested here}}
}
