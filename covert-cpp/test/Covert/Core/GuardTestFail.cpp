// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "../include/MPCLattice.h"
#include "Covert/SE.h"

MPC<int, Everyone> x = 0;
MPC<int, Bob> b = 0;
MPC<int *, Bob, Bob> bp = &b;
SE<int, H> secret = 42;

int main() {
  mpc_guard<AliceBob>(x); // expected-error {{no matching function for call to 'mpc_guard'}}
  mpc_guard<Public>(b); // expected-error {{no matching function for call to 'mpc_guard'}}
  mpc_guard<Bob, Public>(bp); // expected-error {{no matching function for call to 'mpc_guard'}}
  se_guard<L>(secret); // expected-error {{no matching function for call to 'se_guard'}}
}
