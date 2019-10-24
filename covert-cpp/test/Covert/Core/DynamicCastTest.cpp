// RUN: %clang-llvm -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %lli %t.bc | %FileCheck %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

struct Base {
  virtual ~Base() {}
};
struct OtherBase {
  virtual ~OtherBase() {}
};
struct Derived : Base {};

COVERT_LOG_TYPE(Base);
COVERT_LOG_TYPE(OtherBase);
COVERT_LOG_TYPE(Derived);

int main() {
  const SE<Base *, L> b = new Base;
  const SE<OtherBase *, L> ob = new OtherBase;
  const SE<Base *, L> bd = new Derived;
  const SE<Derived *, L> d = new Derived;
  Derived *nonc = new Derived;
  SE<Base *, L> _b = nullptr;
  SE<OtherBase *, L> _ob = nullptr;
  SE<const Base *, L> _cb = nullptr;
  SE<Derived *, L> _d = nullptr;

  logd = &std::cout;

  // 1: exact cast
  TEST(_b = se_dynamic_cast<Base *, L>(b); __COVERT_ASSERT__(_b)) // CHECK: TEST
  // CHECK-NEXT: se_dynamic_cast: 'const SE<Base*, L> &' -> 'SE<Base*, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<Base*, L>(Base*)'{{$}}
  // CHECK: END TEST

  // 1: more cv-qualified cast
  TEST(_cb = se_dynamic_cast<const Base *, L>(b); __COVERT_ASSERT__(_cb);) // CHECK: TEST
  // CHECK-NEXT: se_dynamic_cast: 'const SE<Base*, L> &' -> 'SE<const Base*, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<const Base*, L>(const Base*)'{{$}}
  // CHECK: END TEST

  // 3: upcast (successful)
  TEST(_b = se_dynamic_cast<Base *, L>(d); __COVERT_ASSERT__(_cb);) // CHECK: TEST
  // CHECK-NEXT: se_dynamic_cast: 'const SE<Derived*, L> &' -> 'SE<Base*, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<Base*, L>(Base*)'{{$}}
  // CHECK: END TEST

  // 3: upcast (unsuccessful)
  TEST(_ob = se_dynamic_cast<OtherBase *, L>(d); __COVERT_ASSERT__(!_ob);) // CHECK: TEST
  // CHECK-NEXT: se_dynamic_cast: 'const SE<Derived*, L> &' -> 'SE<OtherBase*, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<OtherBase*, L>(OtherBase*)'{{$}}
  // CHECK: END TEST

  // 5: downcast (successful)
  TEST(_d = se_dynamic_cast<Derived *, L>(bd); __COVERT_ASSERT__(_d);) // CHECK: TEST
  // CHECK-NEXT: se_dynamic_cast: 'const SE<Base*, L> &' -> 'SE<Derived*, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<Derived*, L>(Derived*)'{{$}}
  // CHECK: END TEST

  // 5: (rvalue) downcast (successful)
  TEST(_d = se_dynamic_cast<Derived *, L>(std::move(bd)); __COVERT_ASSERT__(_d);) // CHECK: TEST
  // CHECK-NEXT: se_dynamic_cast: 'const SE<Base*, L>' -> 'SE<Derived*, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<Derived*, L>(Derived*)'{{$}}
  // CHECK: END TEST

  // 5: downcast (unsuccessful)
  TEST(_d = se_dynamic_cast<Derived *, L>(ob); __COVERT_ASSERT__(!_d);) // CHECK: TEST
  // CHECK-NEXT: se_dynamic_cast: 'const SE<OtherBase*, L> &' -> 'SE<Derived*, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<Derived*, L>(Derived*)'{{$}}
  // CHECK: END TEST

  TEST(se_dynamic_cast<Base *, L>(nonc);) // CHECK: TEST
  // CHECK-NEXT: se_dynamic_cast: 'Derived* &' -> 'SE<Base*, L>'{{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<Base*, L>(Base*)'{{$}}
  // CHECK: END TEST
}
