// RUN: %check-cpp2covert -checks=types --

#include "Covert/SE.h"

// Simple multi-decl
void fun1() {
  int x, y, z;
// CHECK-MESSAGES: :[[@LINE-1]]:7: warning: 'x' declared with primitive type 'int'
// CHECK-MESSAGES: :[[@LINE-2]]:10: warning: 'y' declared with primitive type 'int'
// CHECK-MESSAGES: :[[@LINE-3]]:13: warning: 'z' declared with primitive type 'int'
// CHECK-MESSAGES: :[[@LINE-4]]:3: note: suggested rewrite:
// CHECK-FIXES: SE<int, L> x, y, z;
}

// multi-decl with various types, we rewrite the entire DeclStmt
void fun2() {
  int x, *const y = nullptr;
// CHECK-MESSAGES: :[[@LINE-1]]:7: warning: 'x' declared with primitive type 'int'
// CHECK-MESSAGES: :[[@LINE-2]]:17: warning: 'y' declared with primitive type 'int *const'
// CHECK-MESSAGES: :[[@LINE-3]]:3: note: suggested rewrite:
// CHECK-FIXES: SE<int, L> x; const SE<int *, L, L> y = nullptr;
}

// singleton DeclStmt without qualifiers
void fun3() {
  int x;
// CHECK-MESSAGES: :[[@LINE-1]]:7: warning: 'x' declared with primitive type 'int'
// CHECK-FIXES: SE<int, L> x;
}

// singleton DeclStmt with qualifiers
void fun4() {
  int const x = 0;
// CHECK-MESSAGES: :[[@LINE-1]]:13: warning: 'x' declared with primitive type 'const int'
// CHECK-FIXES: const SE<int, L> x = 0;
}

template <typename T>
struct C {
  void foo() {
    T x, *y; // don't transform dependent types
  }
};

void fun5() {
  C<int> c;
  c.foo();
// CHECK-MESSAGES: :[[@LINE-7]]:7: warning: 'x' declared with primitive type 'int'
// CHECK-MESSAGES: :[[@LINE-3]]:10: note: in instantiation of template class 'C<int>' requested here
// CHECK-MESSAGES: :[[@LINE-9]]:11: warning: 'y' declared with primitive type 'int *'
// CHECK-MESSAGES: :[[@LINE-5]]:10: note: in instantiation of template class 'C<int>' requested here
}

// multi-decl with same type, pointer
void fun6() {
  int **x, **y;
// CHECK-MESSAGES: :[[@LINE-1]]:9: warning: 'x' declared with primitive type 'int **'
// CHECK-MESSAGES: :[[@LINE-2]]:14: warning: 'y' declared with primitive type 'int **'
// CHECK-MESSAGES: :[[@LINE-3]]:3: note: suggested rewrite:
// CHECK-FIXES: SE<int **, L, L, L> x, y
}

// multi-decl with same type, pointer, qualifier
void fun7() {
  const int **x, **y;
// CHECK-MESSAGES: :[[@LINE-1]]:15: warning: 'x' declared with primitive type 'const int **'
// CHECK-MESSAGES: :[[@LINE-2]]:20: warning: 'y' declared with primitive type 'const int **'
// CHECK-MESSAGES: :[[@LINE-3]]:3: note: suggested rewrite:
// CHECK-FIXES: SE<const int **, L, L, L> x; SE<const int **, L, L, L> y;
}

// multi-decl with same type, lvalue reference
void fun8() {
  SE<int, L> _x, _y;
  int &x = _x, &y = _y;
// CHECK-MESSAGES: :[[@LINE-1]]:8: warning: 'x' declared with primitive type 'int &'
// CHECK-MESSAGES: :[[@LINE-2]]:17: warning: 'y' declared with primitive type 'int &'
// CHECK-MESSAGES: :[[@LINE-3]]:3: note: suggested rewrite:
// CHECK-FIXES: SE<int, L> &x = _x, &y = _y;
}

#define STMT int *x;
void fun9() {
  STMT;
// CHECK-MESSAGES: :[[@LINE-1]]:3: warning: 'x' declared with primitive type 'int *'
// CHECK-MESSAGES: :[[@LINE-4]]:19: note: expanded from macro 'STMT'
// CHECK-MESSAGES: :[[@LINE-5]]:19: note: use type 'SE<int *, L, L>' instead
}

template <typename T>
void fun10() {
  char *p;
// CHECK-MESSAGES: :[[@LINE-1]]:9: warning: 'p' declared with primitive type 'char *'
// CHECK-FIXES: SE<char *, L, L>
  T v;
}

void fun11() {
  fun10<int>();
// CHECK-MESSAGES: :[[@LINE-5]]:5: warning: 'v' declared with primitive type 'int'
// CHECK-MESSAGES: :[[@LINE-2]]:3: note: in instantiation of function template 'fun10<int>' requested here
// CHECK-MESSAGES: :[[@LINE-7]]:5: note: use type 'SE<int, L>' instead
}

void fun12() {
  const int carr[2] = {0, 1};
// CHECK-MESSAGES: :[[@LINE-1]]:13: warning: 'carr' declared with primitive type 'const int [2]'
// CHECK-FIXES: const SE<int, L> carr[2] = {0, 1};

  const char *const cstr = nullptr;
// CHECK-MESSAGES: :[[@LINE-1]]:21: warning: 'cstr' declared with primitive type 'const char *const'
// CHECK-FIXES: const SE<const char *, L, L> cstr = nullptr;
}
