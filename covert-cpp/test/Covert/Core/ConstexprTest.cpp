// RUN: %clang-syntax -Xclang -verify %s
#include "Covert/SE.h"

// expected-no-diagnostics


constexpr SE<int, L> a = 2, b = 2;
constexpr SE<const int *, L, L> p = &a;

int main() {
  { constexpr auto r = a + b; }
  { constexpr auto r = !a; }
  { constexpr auto r = a < b; }
  { constexpr long r = a; }
  { constexpr SE<long, L> r = a; }
  { constexpr SE<int, H> r = a; }
  { constexpr auto r = &a; }
  { constexpr auto r = a; }
  { constexpr auto r = se_to_primitive(p); }
  { constexpr auto r = se_label_cast<int, H>(a); }
  { constexpr auto r = se_static_cast<long>(a); }
  { constexpr auto r = se_const_cast<int *, L, L>(p); }
  { int arr[a] = {0, 1}; }
}
