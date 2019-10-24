// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<const int *, L, L> clp;
SE<int *, H, H> hp;

int main() {
  SE<int, L> &a = *clp; // expected-error-re {{binding value of type {{.+}} to reference to type {{'.+'}} drops 'const' qualifier}}
  SE<int, H> b = *hp; // expected-error {{indirection requires pointer operand}}
}
