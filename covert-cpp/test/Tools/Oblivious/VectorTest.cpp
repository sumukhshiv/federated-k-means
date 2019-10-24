// RUN: %r/%basename.out | FileCheck %s
#include "../include/Test.h"
#include "ovector.h"

#undef NDEBUG
#include <cassert>

#define LOG(val) *logd << "output: " << (val) << '\n';

using namespace oblivious;

using T = int;
using A = oallocator<T, AllocatorCategory::ContiguousAllocator>;
using X = ovector<int>;
A m;
const X v = {0, 1, 2, 3};
const X t = {4, 5, 6, 7};

int main() {
  logd = &std::cout;

  // check to ensure that ovector satisfies AllocatorAwareContainer

  { // default construction
    X u;
    assert(u.empty() == true && u.get_allocator() == A());
  }

  { // allocator construction
    X u(m);
    assert(u.empty() == true && u.get_allocator() == m);
  }

  { // CopyInsertable
    X u(t, m);
    assert(u == t && u.get_allocator() == m);
    assert(u[2] == 6);
  }

  { // copy construction
    TEST(X v2 = v;) // CHECK: TEST
    // CHECK: oallocator select_on_container_copy_construction
    // CHECK-NEXT: oallocator default constructor
    // CHECK: END TEST
  }

  { // move construction
    X v1 = v;
    TEST(X v2 = std::move(v1);) // CHECK: TEST
    // CHECK: oallocator move constructor
    // CHECK: END TEST

    X v2 = v;
    A v2a = v2.get_allocator();
    X v3 = std::move(v2);
    assert(v3.get_allocator() == v2a);
    assert(v3[2] == 2);
  }

  { // MoveInsertable
    X v1 = v;
    TEST(X v2{std::move(v1), m};) // CHECK: TEST
    // CHECK: oallocator copy constructor
    // CHECK: END TEST

    X v2 = v;
    X v3{std::move(v2), m};
    assert(v3.get_allocator() == m);
    assert(v3[2] == 2);
  }

  { // CopyAssignable
    ovector<int> vv;
    TEST(vv = v;) // CHECK: TEST
    // CHECK-NEXT: END TEST
  }

  { // MoveAssignable
    ovector<int> vv, vvv = v;
    TEST(vv = std::move(vvv);) // CHECK: TEST
    // CHECK-NEXT: oallocator move assignment
    // CHECK-NEXT: END TEST
  }

  { // functionality test
    X _v = v;
    _v.clear();
    TEST(for (int i = 0; i < 8192; ++i) {
      _v.push_back(i);
    } for (int i = 0; i < 8192; i += 997) { LOG(_v[i]); });
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
    _v.resize(1024);
    TEST(LOG(_v[972]);) // CHECK: TEST
    // CHECK-NEXT: output: 972
    // CHECK-NEXT: END TEST
  }

  { // test read beyond chunk
    X _v = v;
    _v.clear();
    TEST(for (int i = 0; i < 1024; ++i) {
      _v.push_back(i);
    } LOG(_v[1000]));
    // CHECK: TEST
    // CHECK-NEXT: output: 1000
    // CHECK-NEXT: END TEST
  }
}
