// RUN: %r/%basename.out
#include "../include/Test.h"
#include "omemory.h"

#undef NDEBUG
#include <cassert>
#include <iostream>

#define PAGE_SIZE 4096

using namespace oblivious;

struct PageNode : public o_mem_node {
  std::size_t num_allocs;
  std::size_t offset;
  PageNode *prev;
};

template <typename F> void traverse(const PageNode *list, F f) {
  for (const PageNode *I = list, *const E = nullptr; I != E;
       I = static_cast<const PageNode *>(I->next)) {
    f(*I);
  }
}

struct R {
  int y;
  int z;
};

using T = int;
using U = R;
using A = oallocator<T, AllocatorCategory::PageAllocator>;
using B = typename std::allocator_traits<A>::rebind_alloc<U>;
A a;
B b = a;

int main() {
  { // allocate, then deallocate
    auto p = a.allocate(4);
    auto r = static_cast<const PageNode *>(a.get_regions());
    assert(r->size == PAGE_SIZE);
    assert(r->offset == 4 * sizeof(T));
    a.deallocate(p, 4);
    assert(!a.get_regions());
  }

  { // allocate twice, then deallocate twice
    auto p = a.allocate(4);
    auto q = a.allocate(8);
    auto r = static_cast<const PageNode *>(a.get_regions());
    assert(r->offset == ((4 + 8) * sizeof(T)));
    assert(a.get_regions());
    a.deallocate(p, 4);
    assert(a.get_regions());
    a.deallocate(q, 8);
    assert(!a.get_regions());
  }

  { // allocate two different types
    auto p = a.allocate(4);
    auto q = b.allocate(8);
    auto r = static_cast<const PageNode *>(a.get_regions());
    assert(r->offset == (4 * sizeof(T) + 8 * sizeof(U)));
    assert(a.get_regions());
    a.deallocate(p, 4);
    assert(a.get_regions());
    b.deallocate(q, 8);
    assert(!a.get_regions());
    assert(!b.get_regions());
  }

  { // one big node
    int x = 0;
    auto CountNodes = [&x](const PageNode &) { ++x; };

    auto p = a.allocate(1024);
    auto r = static_cast<const PageNode *>(a.get_regions());
    traverse(r, CountNodes);
    assert(x == 1);
    assert(r->offset == (1024 * sizeof(T)));
    a.deallocate(p, 1024);
    assert(!a.get_regions());
  }

  { // many nodes
    int x = 0;
    auto CountNodes = [&x](const PageNode &) { ++x; };

    T *p[8];
    for (int i = 0; i < 8; ++i) {
      p[i] = a.allocate(PAGE_SIZE / sizeof(T));
    }
    auto r = static_cast<const PageNode *>(a.get_regions());
    traverse(r, CountNodes);
    assert(x == 8);

    a.deallocate(p[7], PAGE_SIZE / sizeof(T));
    x = 0;
    r = static_cast<const PageNode *>(a.get_regions());
    traverse(r, CountNodes);
    assert(x == 7);

    a.deallocate(p[4], PAGE_SIZE / sizeof(T));
    x = 0;
    r = static_cast<const PageNode *>(a.get_regions());
    traverse(r, CountNodes);
    assert(x == 6);

    a.deallocate(p[0], PAGE_SIZE / sizeof(T));
    x = 0;
    r = static_cast<const PageNode *>(a.get_regions());
    traverse(r, CountNodes);
    assert(x == 5);

    a.deallocate(p[1], PAGE_SIZE / sizeof(T));
    a.deallocate(p[2], PAGE_SIZE / sizeof(T));
    a.deallocate(p[3], PAGE_SIZE / sizeof(T));
    a.deallocate(p[5], PAGE_SIZE / sizeof(T));
    a.deallocate(p[6], PAGE_SIZE / sizeof(T));
    x = 0;
    r = static_cast<const PageNode *>(a.get_regions());
    traverse(r, CountNodes);
    assert(x == 0);
  }

  { // so many nodes
    const int num_allocs = 1 << 16;
    int *ptrs[num_allocs];
    for (int i = 0; i < num_allocs; ++i) {
      ptrs[i] = a.allocate(1024);
    }
    for (int i = 0; i < num_allocs; ++i) {
      a.deallocate(ptrs[i], 1024);
    }
  }
}
