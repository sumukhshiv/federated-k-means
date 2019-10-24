// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s
#include "Covert/SE.h"

int x = 2;

int main() {
  // expected-note-re@Covert/__covert_impl.h:* {{no known conversion from 'int' to '{{.*}}int *{{.*}}'}}
  SE<int *, L, L> p = x; // expected-error {{no viable conversion from 'int' to 'SE<int *, L, L>'}}
}
