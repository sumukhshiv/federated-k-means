// RUN: %check-c2cpp --

enum Bool { True, False };
typedef enum { Tik, Tok } Clock;

void foo(void *ptr) {
  char *p = ptr;
// CHECK-MESSAGES: :[[@LINE-1]]:13: warning: Implicit cast from 'void *' to 'char *' is not allowed in C++
// CHECK-FIXES: char *p = static_cast<char *>(ptr);
  void *v = ptr; // should not produce a warning

#define MACRO(name, arg) const int *name = arg
  MACRO(n, ptr);
// CHECK-MESSAGES: :[[@LINE-1]]:12: warning: Implicit cast from 'void *' to 'const int *' is not allowed in C++
// CHECK-MESSAGES: :[[@LINE-3]]:44: note: expanded from macro 'MACRO'

  int k;
  enum Bool b = k;
// CHECK-MESSAGES: :[[@LINE-1]]:17: warning: Implicit cast from 'int' to 'enum Bool' is not allowed in C++
// CHECK-FIXES: enum Bool b = static_cast<enum Bool>(k);
  Clock c = 1;
// CHECK-MESSAGES: :[[@LINE-1]]:13: warning: Implicit cast from 'int' to 'Clock' is not allowed in C++
// CHECK-FIXES: Clock c = static_cast<Clock>(1);
}
