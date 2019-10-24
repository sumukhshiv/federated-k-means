// RUN: %clang-syntax -Xclang -verify %s

#include "Covert/SE.h"


SE<int *, H, L> p;
SE<int, H> *pp;

int main() {
  { auto res = static_cast<int *>(p); } // expected-error-re {{cannot cast from type 'SE<int *, H, L>'{{.*}} to pointer type 'int *'}}
  { auto res = const_cast<int *>(p); } // expected-error-re {{const_cast from 'SE<int *, H, L>'{{.*}} to 'int *' is not allowed}}
  { auto res = reinterpret_cast<int *>(p); } // expected-error-re {{reinterpret_cast from 'SE<int *, H, L>'{{.*}} to 'int *' is not allowed}}
  { auto res = reinterpret_cast<int *&>(p); } // expected-no-error
  { auto res = reinterpret_cast<int *>(pp); } // expected-no-error
  { auto res = (int *)(p); } // expected-error-re {{cannot cast from type 'SE<int *, H, L>'{{.*}} to pointer type 'int *'}}
}
