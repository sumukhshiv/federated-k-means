// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


struct C {
  int x;
};
C c;
SE<C *, H> cptr = &c;
SE<int *, L, L> kp;

int main() {
  auto r1 = *cptr; // expected-error-re {{indirection requires pointer operand ('SE<C *, H>'{{.*}} invalid)}}
  auto r2 = cptr[0]; // expected-error-re {{no viable overloaded operator[] for type 'SE<C *, H>'{{.*}}}}
  cptr->x = 1; // expected-error {{no viable overloaded 'operator->'}}
  kp->x; // expected-error {{member reference base type 'int' is not a structure or union}}
}
