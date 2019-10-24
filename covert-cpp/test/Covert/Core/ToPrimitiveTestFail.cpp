// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<int, H> a;
SE<const int *, H, L> p;

int main() {
  int b = se_to_primitive(a); // expected-no-error
  int c = se_to_primitive(b); // expected-no-error
  int *ptr = se_to_primitive(p); // expected-error {{cannot initialize a variable of type 'int *' with an lvalue of type 'const int *'}}
}
