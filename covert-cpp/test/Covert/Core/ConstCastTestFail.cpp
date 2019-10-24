// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<const int *, L, L> p;
SE<const SE<int, H> *, L> nonp;

void foo() {
  // 1: invalid type cast
  // expected-note@Covert/SE.h:* {{const_cast from 'const int *' to 'char *' is not allowed}}
  { se_const_cast<char *, L, L>(p); } // expected-error {{no matching function for call to 'se_const_cast'}}

  // 2: Downcast slevels
  // expected-note-re@Covert/SE.h:* {{requirement '{{.*}}is_covert_convertible{{.+}}' was not satisfied}}
  { se_const_cast<const int *, L, L>(nonp); } // expected-error {{no matching function for call to 'se_const_cast'}}
}
