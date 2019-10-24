// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected=note -Xclang -verify-ignore-unexpected=error %s

#include "Covert/SE.h"


struct Base {
  virtual ~Base() {}
};
struct OtherBase {
  virtual ~OtherBase() {}
};
struct Derived : Base {};

void foo() {
  SE<Base *, L> b;
  SE<const Base *, L> cb;
  SE<OtherBase *, L> ob;
  SE<Derived *, L> d;

  // invalid type cast
  // expected-note@Covert/SE.h:* {{'char' is not a class}}
  { se_dynamic_cast<char *>(b); } // expected-error {{no matching function for call to 'se_dynamic_cast'}}

  // 1: cast away cv-qualifiers
  // expected-note@Covert/SE.h:* {{dynamic_cast from 'const Base *' to 'Derived *' casts away qualifiers}}
  { se_dynamic_cast<Derived *>(cb); } // expected-error {{no matching function for call to 'se_dynamic_cast'}}
}
