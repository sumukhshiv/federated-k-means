// RUN: %check-cpp2covert -checks=types --

#include "Covert/SE.h"

class Outer {
  class Inner {};

  Inner *i1;
// CHECK-MESSAGES: :[[@LINE-1]]:10: warning: 'i1' declared with primitive type 'Outer::Inner *'
// CHECK-FIXES: SE<Inner *, L> i1;
  Outer::Inner *i2;
// CHECK-MESSAGES: :[[@LINE-1]]:17: warning: 'i2' declared with primitive type 'Outer::Inner *'
// CHECK-FIXES: SE<Outer::Inner *, L> i2;
};

template <typename T>
struct OuterT {
  class Inner {};

  Inner *c1;
// CHECK-MESSAGES: :[[@LINE-1]]:10: warning: 'c1' declared with primitive type 'OuterT::Inner *'
// CHECK-FIXES: SE<Inner *, L> c1;
  OuterT::Inner *c2;
// CHECK-MESSAGES: :[[@LINE-1]]:18: warning: 'c2' declared with primitive type 'OuterT<T>::Inner *'
// CHECK-FIXES: SE<OuterT<T>::Inner *, L> c2;
};
