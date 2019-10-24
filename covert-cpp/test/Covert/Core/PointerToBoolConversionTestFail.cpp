// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"

SE<int *, H, L> flp = nullptr;

int main() {
  bool b = flp; // expected-error {{no viable conversion}}
}
