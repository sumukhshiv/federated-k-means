// RUN: %clang-syntax -Xclang -verify %s
#include "Covert/SE.h"

int main() {
  { SE<int &[], L> array; } // expected-error {{'type name' declared as array of references of type 'int &'}}
  // expected-error@Covert/__covert_impl.h:* {{Incorrect number of labels for this type}}
  { SE<int, L, H> x; } // expected-note-re {{in instantiation of template class '{{.+}}' requested here}}
  // expected-error@Covert/__covert_impl.h:* {{Cannot encapsulate a const and/or volatile type}}
  { SE<const int, L> y; } // expected-note-re {{in instantiation of template class '{{.+}}' requested here}}
  // expected-error@Covert/__covert_impl.h:* {{Cannot encapsulate a reference type}}
  { SE<int &, L> y; } // expected-note-re {{in instantiation of template class '{{.+}}' requested here}}
  // expected-error@Covert/__covert_impl.h:* {{Cannot encapsulate an array type}}
  { SE<int [12], L> y; } // expected-note-re {{in instantiation of template class '{{.+}}' requested here}}
}
