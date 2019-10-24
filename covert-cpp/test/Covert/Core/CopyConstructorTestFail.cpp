// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<void *, L> vp;
SE<int, L> x = 2;

int main() {
  SE<int *, L, L> p = x; // expected-error-re {{no viable conversion from '{{.+}}' to '{{.+}}'}}
  SE<char *, L, L> cp = vp; // expected-error-re {{no viable conversion from '{{.+}}' to '{{.+}}'}}
}
