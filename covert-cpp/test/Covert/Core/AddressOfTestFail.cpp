// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"

SE<int, H> a;
const SE<int, H> ca = 2;

int main() {
  SE<int *, L, L> pa = &a; // expected-error-re {{no viable conversion from '{{.+}}' to '{{.+}}'}}
  SE<const int *, L, L> pca = &ca; // expected-error-re {{no viable conversion from '{{.+}}' to '{{.+}}'}}
}
