// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s
#include "Covert/SE.h"


int main() {
  const SE<int, L> arr[4] = {0, 1, 2, 3};
  SE<int *, L, L> p = arr; // expected-error-re {{no viable conversion from '{{.+}}' to '{{.+}}'}}
}
