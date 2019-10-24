// RUN: %r/%basename.out
#include "../include/Test.h"
#include "omemory.h"

#undef NDEBUG
#include <cassert>

using namespace oblivious;

struct R {
  int y;
  int z;
};

using T = int;
using U = R;
using A = oallocator<T, AllocatorCategory::ContiguousAllocator>;
using B = typename std::allocator_traits<A>::rebind_alloc<U>;
A a;
B b = a;

int main() {
  { // allocate, then deallocate
    auto p = a.allocate(32);
    auto r = a.get_regions();
    assert(r->size == (32 * sizeof(T)));
    a.deallocate(p, 32);
    assert(!a.get_regions());
  }

  { // allocate twice, then deallocate twice
    auto p = a.allocate(32);
    auto q = a.allocate(64);
    auto r = a.get_regions();
    assert(r->size == (64 * sizeof(T)));
    a.deallocate(p, 32);
    assert(a.get_regions());
    a.deallocate(q, 64);
    assert(!a.get_regions());
  }

  { // allocate two different types
    auto p = a.allocate(32);
    auto q = b.allocate(64);
    auto r = a.get_regions();
    assert(r->size == (64 * sizeof(U)));
    a.deallocate(p, 32);
    assert(a.get_regions());
    b.deallocate(q, 64);
    assert(!a.get_regions());
  }

  { // allocate a lot of data
    auto p = a.allocate(1 << 24);
    a.deallocate(p, 1 << 24);
  }
}
