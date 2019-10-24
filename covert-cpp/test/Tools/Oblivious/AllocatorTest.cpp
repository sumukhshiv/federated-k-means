// RUN: %r/%basename.out
#include "../include/Test.h"
#include "omemory.h"

#undef NDEBUG
#include <cassert>

using namespace oblivious;

// check that O_Allocator satisfies the Allocator concept requirements

struct S {
  int m;
};
struct R {
  int y;
  int z;
};

using T = S;
using U = R;
using A = oallocator<T>;
using B = typename std::allocator_traits<A>::rebind_alloc<U>;
A a;
B b;
T x{42};
typename std::allocator_traits<A>::size_type n = 1024;

int main() {
  typename std::allocator_traits<A>::pointer ptr = &x;
  static_assert(std::is_same<decltype(*ptr), T &>::value, "");

  typename std::allocator_traits<A>::const_pointer cptr = ptr;
  static_assert(std::is_same<decltype(*cptr), const T &>::value, "");
  assert(&*cptr == &*ptr);

  static_assert(std::is_same<decltype(ptr->m), decltype(T::m)>::value, "");
  assert(ptr->m == (*ptr).m);

  static_assert(std::is_same<decltype(cptr->m), decltype(T::m)>::value, "");
  assert(cptr->m == (*cptr).m);

  typename std::allocator_traits<A>::void_pointer vptr = ptr;
  static_assert(
      std::is_same<decltype(static_cast<
                            typename std::allocator_traits<A>::pointer>(vptr)),
                   typename std::allocator_traits<A>::pointer>::value,
      "");
  assert(static_cast<typename std::allocator_traits<A>::pointer>(vptr) == ptr);

  typename std::allocator_traits<A>::const_void_pointer cvptr = vptr;
  static_assert(
      std::is_same<decltype(static_cast<typename std::allocator_traits<
                                A>::const_pointer>(cvptr)),
                   typename std::allocator_traits<A>::const_pointer>::value,
      "");
  assert(static_cast<typename std::allocator_traits<A>::const_pointer>(cvptr) ==
         cptr);

  {
    static_assert(
        std::is_same<decltype(a.allocate(n)),
                     typename std::allocator_traits<A>::pointer>::value,
        "");
    typename std::allocator_traits<A>::pointer p = a.allocate(n);
    for (int i = 0; i < n; ++i) {
      p[i].m = i;
    }

    a.deallocate(p, n);
  }

  {
    A a1, a2;
    assert((a1 != a2) == !(a1 == a2));
  }

  {
    A a1(a);
    assert(a1 == a);
    A a2 = a;
    assert(a2 == a);
  }

  {
    A a1(b);
    assert((B(a1) == b) && (A(b) == a1));
  }

  {
    A a1(std::move(a));
    assert(a1 == a);
    A a2 = std::move(a);
    assert(a2 == a);
  }

  {
    A a1(std::move(b));
    assert(a1 == b);
  }

  {
    A a1 = a.select_on_container_copy_construction();
    auto p = a1.allocate(1);
    assert(a1 != a);
    a1.deallocate(p, 1);
  }

  // Must satisfy MoveAssignable, since propagate_on_container_move_assignment
  // == std::true_type
  {
    A t;
    t = std::move(a);
    assert(t == a);
    static_assert(std::is_same<decltype(t = std::move(a)), A &>::value, "");
  }

  // Must satisfy Swappable, since propagate_on_container_swap == std::true_type
  {
    using std::swap;
    A u, t;
    A _u = u, _t = t;
    swap(u, t);
    assert(u == _t && t == _u);
    swap(t, u);
    assert(t == _t && u == _u);
  }
}
