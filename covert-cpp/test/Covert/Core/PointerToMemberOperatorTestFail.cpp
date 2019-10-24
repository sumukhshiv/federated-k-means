// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


struct S {
  S(SE<int, L> n) : mi(n) {}
  mutable SE<int, L> mi;
  SE<int, L> f(SE<int, L> n) { return mi + n; }
};

struct D : public S {
  D(SE<int, L> n) : S(n) {}
};

int main() {
  SE<int, L>(S::*pf)(SE<int, L>) = &S::f;

  D d(7);
  SE<D *, H> pd = &d;

  (pd->*(pf))(8); // expected-error {{left hand operand to ->* must be a pointer to class compatible with the right hand operand}}
}
