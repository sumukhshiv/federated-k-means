// RUN: %r/%basename.out | FileCheck %s
#include "../include/Test.h"
#include "oforward_list.h"
#include <algorithm>

#undef NDEBUG
#include <cassert>

#define LOG(val) *logd << "output: " << (val) << '\n';

using namespace oblivious;

using T = int;
using X = oforward_list<int>;
using A = typename X::allocator_type;
A m;
const X x = {0, 1, 2, 3};
const X t = {4, 5, 6, 7};

int main() {
  logd = &std::cout;

  // check to ensure that oforward_list satisfies AllocatorAwareContainer

  { // default construction
    X u;
    assert(u.empty() == true);
    // assert(u.get_allocator() == A()); does NOT satisfy this requirement
  }

  { // allocator construction
    X u(m);
    assert(u.empty() == true && u.get_allocator() == m);
  }

  { // CopyInsertable
    X u(t, m);
    assert(u == t && u.get_allocator() == m);
    assert(*u.begin() == 4);
  }

  {                 // copy construction
    TEST(X x2 = x;) // CHECK: TEST
    // CHECK: oallocator select_on_container_copy_construction
    // CHECK-NEXT: oallocator default constructor
    // CHECK: END TEST
  }

  { // move construction
    X x1 = x;
    TEST(X x2 = std::move(x1);) // CHECK: TEST
    // CHECK: oallocator move constructor
    // CHECK: END TEST

    X x2 = x;
    A x2a = x2.get_allocator();
    X x3 = std::move(x2);
    assert(x3.get_allocator() == x2a);
    assert(*x3.begin() == 0);
  }

  { // MoveInsertable
    X x1 = x;
    TEST(X x2{std::move(x1), m};) // CHECK: TEST
    // CHECK: oallocator template copy constructor
    // CHECK: END TEST

    X x2 = x;
    X x3{std::move(x2), m};
    assert(x3.get_allocator() == m);
    assert(*x3.begin() == 0);
  }

  { // CopyAssignable
    oforward_list<int> xx;
    TEST(xx = x;) // CHECK: TEST
    // CHECK-NEXT: END TEST
  }

  { // MoveAssignable
    oforward_list<int> xx, xxx = x;
    TEST(xx = std::move(xxx);) // CHECK: TEST
    // CHECK-NEXT: oallocator move assignment
    // CHECK-NEXT: END TEST
  }

  { // functionality test
    X _x = x;
    _x.clear();
    TEST(for (int i = 8192 - 1; i >= 0; --i) { _x.push_front(i); } int i = 0;
         std::for_each(_x.begin(), _x.end(), [&i](int v) {
           if (i++ % 997 == 0)
             LOG(v);
         }));
    // CHECK: TEST
    // CHECK-NEXT: output: 0
    // CHECK-NEXT: output: 997
    // CHECK-NEXT: output: 1994
    // CHECK-NEXT: output: 2991
    // CHECK-NEXT: output: 3988
    // CHECK-NEXT: output: 4985
    // CHECK-NEXT: output: 5982
    // CHECK-NEXT: output: 6979
    // CHECK-NEXT: output: 7976
    // CHECK-NEXT: END TEST
  }
}
