// RUN: %check-cpp2covert -checks=casting --

#include "Covert/SE.h"

SE<const char *, H, L> cstr;
SE<unsigned long, H> u;
class Base {
  virtual void foo();
};
class Derived {
  void foo();
};
SE<Base *, H> bptr;

void foo() {
  auto str = const_cast<char *>(cstr);
  // CHECK-MESSAGES: :[[@LINE-1]]:14: warning: use 'se_const_cast' instead
  // CHECK-FIXES: auto str = se_const_cast<char *>(cstr);

  auto uu = reinterpret_cast<void *>(u);
  // CHECK-MESSAGES: :[[@LINE-1]]:13: warning: use 'se_reinterpret_cast' instead
  // CHECK-FIXES: auto uu = se_reinterpret_cast<void *>(u);

  auto vptr = static_cast<const void *>(cstr);
  // CHECK-MESSAGES: :[[@LINE-1]]:15: warning: use 'se_static_cast' instead
  // CHECK-FIXES: auto vptr = se_static_cast<const void *>(cstr);

  auto dptr = dynamic_cast<Derived *>(bptr);
  // CHECK-MESSAGES: :[[@LINE-1]]:15: warning: use 'se_dynamic_cast' instead
  // CHECK-FIXES: auto dptr = se_dynamic_cast<Derived *>(bptr);
}
