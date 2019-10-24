// RUN: %check-c2cpp --

typedef int class;
// CHECK-MESSAGES: :[[@LINE-1]]:13: warning: 'class' conflicts with C++ keyword
// CHECK-FIXES: typedef int _class;

struct my_struct {
  int using;
// CHECK-MESSAGES: :[[@LINE-1]]:7: warning: 'using' conflicts with C++ keyword
// CHECK-FIXES: int _using;
};

void template() {
// CHECK-MESSAGES: :[[@LINE-1]]:6: warning: 'template' conflicts with C++ keyword
// CHECK-FIXES: void _template() {
  const class *this = 0;
// CHECK-MESSAGES: :[[@LINE-1]]:16: warning: 'this' conflicts with C++ keyword
// CHECK-MESSAGES: :[[@LINE-2]]:9: warning: 'class' conflicts with C++ keyword
// CHECK-FIXES: const _class *_this = 0;
  ++this;
// CHECK-MESSAGES: :[[@LINE-1]]:5: warning: 'this' conflicts with C++ keyword
// CHECK-FIXES: ++_this;
}

void foo() {
#define CALL_TEMPLATE template()
  CALL_TEMPLATE;
// CHECK-MESSAGES: :[[@LINE-1]]:3: warning: 'template' conflicts with C++ keyword
// CHECK-MESSAGES: :[[@LINE-3]]:23: note: use '_template' instead
  struct my_struct m;
  m.using = 42;
// CHECK-MESSAGES: :[[@LINE-1]]:5: warning: 'using' conflicts with C++ keyword
// CHECK-FIXES: m._using = 42;
}
