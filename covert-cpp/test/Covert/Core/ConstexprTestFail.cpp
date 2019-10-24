// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note %s
#include "Covert/SE.h"

constexpr SE<int, L> *p = 0;
constexpr SE<int, L> i = 0;
void foo();
constexpr void (*foop)() = &foo;

int main() {
  { constexpr int *r = se_to_primitive(p); } // expected-error {{constexpr variable 'r' must be initialized by a constant expression}}
  { constexpr auto r = se_reinterpret_cast<const short &, L>(i); } // expected-error {{constexpr variable 'r' must be initialized by a constant expression}}
  { constexpr void (*r)() = covert::fp_cast(foop); } // expected-error {{constexpr variable 'r' must be initialized by a constant expression}}
  { constexpr SE<int *, L, L> r = p; } // expected-error {{constexpr variable 'r' must be initialized by a constant expression}}
}
