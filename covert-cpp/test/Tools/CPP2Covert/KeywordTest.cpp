// RUN: %check-cpp2covert -checks=keywords --

struct S {
  int H;
// CHECK-MESSAGES: :[[@LINE-1]]:7: warning: Name 'H' conflicts with Covert C++ keyword
// CHECK-FIXES: int _H;
} s;

void L() {
// CHECK-MESSAGES: :[[@LINE-1]]:6: warning: Name 'L' conflicts with Covert C++ keyword
// CHECK-FIXES: void _L() {
  int SE = 4;
// CHECK-MESSAGES: :[[@LINE-1]]:7: warning: Name 'SE' conflicts with Covert C++ keyword
// CHECK-FIXES: int _SE = 4;
  ++SE;
// CHECK-MESSAGES: :[[@LINE-1]]:5: warning: Name 'SE' conflicts with Covert C++ keyword
// CHECK-FIXES: ++_SE;
  L();
// CHECK-MESSAGES: :[[@LINE-1]]:3: warning: Name 'L' conflicts with Covert C++ keyword
// CHECK-FIXES: _L();
  s.H = 2;
// CHECK-MESSAGES: :[[@LINE-1]]:5: warning: Name 'H' conflicts with Covert C++ keyword
// CHECK-FIXES: s._H = 2;
}

#define ACLASS(name) class se_to_##name {};
ACLASS(primitive)
// CHECK-MESSAGES: :[[@LINE-1]]:1: warning: Name 'se_to_primitive' conflicts with Covert C++ keyword
// CHECK-MESSAGES: :[[@LINE-3]]:28: note: expanded from macro 'ACLASS'

template <typename T>
class bar {
  using se_static_cast = T;
// CHECK-MESSAGES: :[[@LINE-1]]:9: warning: Name 'se_static_cast' conflicts with Covert C++ keyword
// CHECK-FIXES: using _se_static_cast = T;

  static const se_static_cast value;
// CHECK-MESSAGES: :[[@LINE-1]]:16: warning: Name 'se_static_cast' conflicts with Covert C++ keyword
// CHECK-FIXES: static const _se_static_cast value;
};
