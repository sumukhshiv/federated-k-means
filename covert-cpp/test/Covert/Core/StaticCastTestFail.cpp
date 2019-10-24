// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<int, L> x;
SE<int *, L, H> hp;

void foo() {
  // 1: Invalid type cast
  // expected-note@Covert/SE.h:* {{cannot cast from type 'int' to pointer type 'int *'}}
  { auto r = se_static_cast<int *, L, L>(x); } // expected-error {{no matching function for call to 'se_static_cast'}}

  // 2: Casting away H labels
  // expected-note-re@Covert/SE.h:* {{requirement '{{.*}}is_covert_convertible{{.+}}' was not satisfied}}
  { auto r = se_static_cast<void *, L>(hp); } // expected-error {{no matching function for call to 'se_static_cast'}}
}
