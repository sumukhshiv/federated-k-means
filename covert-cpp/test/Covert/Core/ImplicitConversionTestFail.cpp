// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/SE.h"


SE<int, H> a;
SE<int, L> al;
SE<int **, L, H, L> p;

int main() {
  int b = a; // expected-error-re {{no viable conversion from 'SE<int, H>'{{.*}} to 'int'}}
  int *ptr2 = al; // expected-error-re {{no viable conversion from 'SE<int, L>'{{.*}} to 'int *'}}
  int **ptr3 = p; // expected-error-re {{no viable conversion from 'SE<int **, L, H, L>'{{.*}} to 'int **'}}
}
