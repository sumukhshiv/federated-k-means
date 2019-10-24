// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


struct S {
  SE<int, L> x;
};
const S cs {2};
SE<const S *, L> cps = &cs;
SE<const S *, H> hps = &cs;

int main() {
  SE<int, L> &a = cps->x; // expected-error {{binding value of type 'const SE<...>' to reference to type 'SE<...>' drops 'const' qualifier}}
  SE<int, H> b = hps->x; // expected-error {{no viable overloaded 'operator->'}}
}
