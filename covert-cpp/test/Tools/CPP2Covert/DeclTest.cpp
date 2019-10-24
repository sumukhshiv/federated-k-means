// RUN: %check-cpp2covert -checks=types --

#define MACRO(Name, Type) Type Name = 0;

#include "Covert/SE.h"
#include <cstdint>

template <int ITEM_SIZE>
class DepT {
  char item[ITEM_SIZE];
// CHECK-MESSAGES: :[[@LINE-1]]:8: warning: 'item' declared with primitive type 'char [ITEM_SIZE]'
// CHECK-FIXES: SE<char, L> item[ITEM_SIZE];
};

DepT<2> dd; // should not produce a warning

MACRO(m1, const int *);
// CHECK-MESSAGES: :[[@LINE-1]]:7: warning: 'm1' declared with primitive type 'const int *'
// CHECK-MESSAGES: :[[@LINE-2]]:7: note: use type 'SE<const int *, L, L>' instead

MACRO(m2, int *);
// CHECK-MESSAGES: :[[@LINE-1]]:7: warning: 'm2' declared with primitive type 'int *'
// CHECK-MESSAGES: :[[@LINE-2]]:7: note: use type 'SE<int *, L, L>' instead

class foo {
#define MACRO2 int _i;
  MACRO2;
// CHECK-MESSAGES: :[[@LINE-1]]:3: warning: '_i' declared with primitive type 'int'
// CHECK-MESSAGES: :[[@LINE-3]]:20: note: expanded from macro 'MACRO2'
// CHECK-MESSAGES: :[[@LINE-4]]:20: note: use type 'SE<int, L>' instead
};

class bar {
#define MACRO3 MACRO2;
  MACRO3;
// CHECK-MESSAGES: :[[@LINE-1]]:3: warning: '_i' declared with primitive type 'int'
// CHECK-MESSAGES: :[[@LINE-3]]:16: note: expanded from macro 'MACRO3'
// CHECK-MESSAGES: :[[@LINE-12]]:20: note: expanded from macro 'MACRO2'
// CHECK-MESSAGES: :[[@LINE-13]]:20: note: use type 'SE<int, L>' instead
};

template <typename T>
class TClass {
  T *x;
};

TClass<int> TC;
// CHECK-MESSAGES: :[[@LINE-4]]:6: warning: 'x' declared with primitive type 'int *'
// CHECK-MESSAGES: :[[@LINE-2]]:13: note: in instantiation of template class 'TClass<int>' requested here
// CHECK-MESSAGES: :[[@LINE-6]]:6: note: use type 'SE<int *, L, L>' instead

class C {
  const static int x; // do not rewrite static const decls

  char *const str = nullptr;
// CHECK-MESSAGES: :[[@LINE-1]]:15: warning: 'str' declared with primitive type 'char *const'
// CHECK-FIXES: const SE<char *, L, L> str = nullptr

  int bitfield : 1; // bitfields are not transformed
};

std::nullptr_t nptr; // nullptrs are not transformed
void foo(void); // void vardecl's are not transformed
C Carr[2]; // arrays of non-primitives are not transformed
C &Cref = Carr[0]; // references to non-primitives are not transformed
void (*blah)(void); // function pointers are not transformed

typedef const int*const cint_ptr; // typedefs are not transformed
typedef const int* int_ptr; // typedefs are not transformed

cint_ptr pp = nullptr; // do not rewrite static const decls

int_ptr _pp = nullptr;
// CHECK-MESSAGES: :[[@LINE-1]]:9: warning: '_pp' declared with primitive type 'int_ptr' (aka 'const int *')
// CHECK-FIXES: SE<int_ptr, L, L>

int k = 4;
// CHECK-MESSAGES: :[[@LINE-1]]:5: warning: 'k' declared with primitive type 'int'
// CHECK-FIXES: SE<int, L> k = 4;

int *p = &k;
// CHECK-MESSAGES: :[[@LINE-1]]:6: warning: 'p' declared with primitive type 'int *'
// CHECK-FIXES: SE<int *, L, L> p = &k;

int &r = *p;
// CHECK-MESSAGES: :[[@LINE-1]]:6: warning: 'r' declared with primitive type 'int &'
// CHECK-FIXES: SE<int, L> &r = *p;

const int &cr = *p;
// CHECK-MESSAGES: :[[@LINE-1]]:12: warning: 'cr' declared with primitive type 'const int &'
// CHECK-FIXES: const SE<int, L> &cr = *p;

int arr[2];
// CHECK-MESSAGES: :[[@LINE-1]]:5: warning: 'arr' declared with primitive type 'int [2]'
// CHECK-FIXES: SE<int, L> arr[2];

int *fun1();
// CHECK-MESSAGES: :[[@LINE-1]]:6: warning: 'fun1' declared with primitive type 'int *'
// CHECK-FIXES: SE<int *, L, L> fun1();

const int *const fun2();
// CHECK-MESSAGES: :[[@LINE-1]]:18: warning: 'fun2' declared with primitive type 'const int *const'
// CHECK-MESSAGES: :[[@LINE-2]]:18: note: use type 'const SE<const int *, L, L>' instead

template <typename T>
T foot() { return 0; };

void test_foot() {
  foot<int>();
// CHECK-MESSAGES: :[[@LINE-4]]:3: warning: 'foot<int>' declared with primitive type 'int'
// CHECK-MESSAGES: :[[@LINE-2]]:3: note: in instantiation of function template 'foot<int>' requested here
// CHECK-MESSAGES: :[[@LINE-6]]:3: note: use type 'SE<int, L>' instead
}

template <typename T>
char *footp() { return 0; };
// CHECK-MESSAGES: :[[@LINE-1]]:7: warning: 'footp' declared with primitive type 'char *'
// CHECK-FIXES: SE<char *, L, L> footp() { return 0; };

void test_footp() {
  footp<int>(); // do not warn, because the warning is instantiation-independent
}

void test_unnamed_params(void *, uint8_t);
// CHECK-MESSAGES: :[[@LINE-1]]:32: warning: Parameter declared with primitive type 'void *'
// CHECK-MESSAGES: :[[@LINE-2]]:41: warning: Parameter declared with primitive type 'uint8_t' (aka 'unsigned char')
// CHECK-FIXES: void test_unnamed_params(SE<void *, L>, SE<uint8_t, L>);

//////////
// Test SECRET annotation

void abcd() {
  { int x SECRET; }
// CHECK-MESSAGES: :[[@LINE-1]]:9: warning: 'x' declared with primitive type 'int'
// CHECK-FIXES: SE<int, H> x SECRET;
  { SECRET int x; }
// CHECK-MESSAGES: :[[@LINE-1]]:16: warning: 'x' declared with primitive type 'int'
// CHECK-FIXES: SECRET SE<int, H> x;
  { SECRET int *x; }
// CHECK-MESSAGES: :[[@LINE-1]]:17: warning: 'x' declared with primitive type 'int *'
// CHECK-FIXES: SECRET SE<int *, L, H> x;
  { SECRET int **x; }
// CHECK-MESSAGES: :[[@LINE-1]]:18: warning: 'x' declared with primitive type 'int **'
// CHECK-FIXES: SECRET SE<int **, L, L, H> x;
}

int secret_func() SECRET;
// CHECK-MESSAGES: :[[@LINE-1]]:5: warning: 'secret_func' declared with primitive type 'int'
// CHECK-FIXES: SE<int, H> secret_func() SECRET;
