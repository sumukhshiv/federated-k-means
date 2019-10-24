// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<const int *, L, L> cp;
SE<SE<int, H> **, L, L> nonp;

void foo() {
  // invalid type cast
  // expected-note@Covert/SE.h:* {{reinterpret_cast from 'const int *' to 'long *' casts away qualifiers}}
  { se_reinterpret_cast<long *>(cp); } // expected-error {{no matching function for call to 'se_reinterpret_cast'}}

  // cast away H labels
  // expected-note-re@Covert/SE.h:* {{requirement '{{.*}}is_covert_convertible{{.+}}' was not satisfied}}
  { se_reinterpret_cast<int *&>(nonp); } // expected-error {{no matching function for call to 'se_reinterpret_cast'}}
}
