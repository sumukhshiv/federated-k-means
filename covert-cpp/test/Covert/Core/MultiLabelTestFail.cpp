// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"
#include "../include/MPCLattice.h"

SE<int, H> h;

int main() {
  { MPC<int, Everyone> r = h; } // expected-error-re {{no viable conversion from '{{.+}}' to '{{.+}}'}}
  { MPC<SE<int, H> *, Bob> r = &h; } // expected-error-re {{no viable conversion from '{{.+}}' to '{{.+}}'}}
}
