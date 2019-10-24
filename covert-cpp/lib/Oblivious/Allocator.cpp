//===------------ Allocator.cpp - libOblivious heap allocator -------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifdef _MSC_VER
#define _ENABLE_EXTENDED_ALIGNED_STORAGE
#endif

#include "omemory.h"
#include <cstdint>
#include <cassert>
#include <iostream>
#include <unordered_map>

namespace oblivious {

#define PAGE_SIZE 4096

using Block = std::aligned_storage_t<BLOCK_SIZE, BLOCK_SIZE>;
using Page = std::aligned_storage_t<PAGE_SIZE, PAGE_SIZE>;

#define IS_PAGE_ALIGNED(addr) (((intptr_t)addr & (sizeof(Page) - 1)) == 0)
#define IS_BLOCK_ALIGNED(addr) (((intptr_t)addr & (sizeof(Block) - 1)) == 0)
#define BLOCKS_PER_PAGE (sizeof(Page) / sizeof(Block))

class ContiguousAllocator : public AllocatorI {
  o_mem_node *__node;

  inline std::size_t get_num_blocks(std::size_t n,
                                    std::size_t object_size) const {
    return ((n * object_size) + (sizeof(Block) - 1)) / sizeof(Block);
  }

public:
  EXPORT ContiguousAllocator();
  EXPORT ~ContiguousAllocator();

  EXPORT void dump_state() const override;
  EXPORT std::size_t size() const override;
  EXPORT const o_mem_node *get_regions() const override;
  EXPORT void *allocate(std::size_t n, std::size_t object_size,
                 std::size_t align) override;
  EXPORT void deallocate(void *p, std::size_t n, std::size_t object_size) override;
};

ContiguousAllocator::ContiguousAllocator() : __node(nullptr) {}

ContiguousAllocator::~ContiguousAllocator() {
  if (__node) {
    delete __node;
  }
}

void ContiguousAllocator::dump_state() const {
  std::cout << "ContiguousAllocator\n";
  std::cout << "===================\n";
  std::cout << "base_addr: " << __node->base_addr << '\n';
  std::cout << "size: " << __node->size << '\n';
}

std::size_t ContiguousAllocator::size() const { return __node->size; }

const o_mem_node *ContiguousAllocator::get_regions() const { return __node; }

void *ContiguousAllocator::allocate(std::size_t n, std::size_t object_size,
                                    std::size_t align) {
  const std::size_t num_blocks = get_num_blocks(n, object_size);
  Block *NewBlocks = new Block[num_blocks];
  assert(IS_BLOCK_ALIGNED(NewBlocks));
  if (!__node) {
    __node = new o_mem_node{nullptr, NewBlocks, num_blocks * sizeof(Block)};
  } else {
    __node->base_addr = NewBlocks;
    __node->size = num_blocks * sizeof(Block);
  }
  return NewBlocks;
}

void ContiguousAllocator::deallocate(void *p, std::size_t n,
                                     std::size_t object_size) {
  delete[] static_cast<Block *>(p);
  if (__node && p == __node->base_addr) {
    delete __node;
    __node = nullptr;
  }
}

class PageAllocator : public AllocatorI {
  struct PageNode : public o_mem_node {
    std::size_t num_allocs;
    std::size_t offset;
    PageNode *prev;
    PageNode(const o_mem_node &node, PageNode *prev,
             std::size_t init_offset = 0)
        : o_mem_node(node), num_allocs(init_offset ? 1 : 0),
          offset(init_offset), prev(prev) {}
  };
  PageNode *__nodes;
  std::unordered_map<Page *, PageNode *> __lookup;

  inline std::size_t get_num_pages(std::size_t n,
                                   std::size_t object_size) const {
    return ((n * object_size) + (sizeof(Page) - 1)) / sizeof(Page);
  }

public:
  EXPORT PageAllocator();
  EXPORT ~PageAllocator();

  EXPORT void dump_state() const override;
  EXPORT std::size_t size() const override;
  EXPORT const o_mem_node *get_regions() const override;
  EXPORT void *allocate(std::size_t n, std::size_t object_size,
                 std::size_t align) override;
  EXPORT void deallocate(void *p, std::size_t n, std::size_t object_size) override;
};

PageAllocator::PageAllocator() : __nodes(nullptr), __lookup() {}

PageAllocator::~PageAllocator() {
  for (PageNode *N, *I = __nodes, *const E = nullptr; I != E; I = N) {
    N = static_cast<PageNode *>(I->next);
    delete I;
  }
}

void PageAllocator::dump_state() const {
  std::cout << "PageAllocator\n";
  std::cout << "==============\n";
  int i = 0;
  for (const PageNode *I = __nodes, *const E = nullptr; I != E;
       I = static_cast<const PageNode *>(I->next)) {
    std::cout << "Node " << i << '\n';
    std::cout << "base_addr: " << I->base_addr << '\n';
    std::cout << "size: " << I->size << '\n';
    std::cout << "num_allocs: " << I->num_allocs << '\n';
    std::cout << "offset: " << I->offset << '\n';
    std::cout << "--------------\n";
    ++i;
  }
}

std::size_t PageAllocator::size() const {
  std::size_t sz = 0;
  for (PageNode *I = __nodes, *const E = nullptr; I != E;
       I = static_cast<PageNode *>(I->next)) {
    sz += I->size;
  }
  return sz;
}

const o_mem_node *PageAllocator::get_regions() const { return __nodes; }

void *PageAllocator::allocate(std::size_t n, std::size_t object_size,
                              std::size_t align) {
  void *mem;
  const std::size_t num_pages = get_num_pages(n, object_size);
  if (!__nodes) {
    Page *NewPage = new Page[num_pages];
    assert(IS_PAGE_ALIGNED(NewPage));
    PageNode *NewNode = new PageNode({nullptr, NewPage, num_pages * sizeof(Page)},
                                     nullptr, n * object_size);
    __lookup.insert({NewPage, NewNode});
    __nodes = NewNode;
    mem = NewPage;
  } else if (__nodes->offset + (n * object_size) > __nodes->size) {
    Page *NewPage = new Page[num_pages];
    assert(IS_PAGE_ALIGNED(NewPage));
    PageNode *NewNode = new PageNode({__nodes, NewPage, num_pages * sizeof(Page)},
                                     nullptr, n * object_size);
    __lookup.insert({NewPage, NewNode});
    __nodes->prev = NewNode;
    __nodes = NewNode;
    mem = NewPage;
  } else {
    mem = reinterpret_cast<void *>(
        reinterpret_cast<intptr_t>(__nodes->base_addr) + __nodes->offset);
    __nodes->offset += n * object_size;
    if (__nodes->offset % align) {
      __nodes->offset += align - __nodes->offset % align;
    }
    __nodes->num_allocs++;
  }
  return mem;
}

/**
 * \details With debugging enabled (`NDEBUG` not defined), this function
 * asserts that \p p falls within a region tracked by this allocator.
 */
void PageAllocator::deallocate(void *p, std::size_t n,
                               std::size_t object_size) {
  void *page_addr = reinterpret_cast<void *>(reinterpret_cast<intptr_t>(p) &
                                        ~(sizeof(Page) - 1));
  auto res = __lookup.find(static_cast<Page *>(page_addr));
  assert(res != __lookup.end());
  Page *page = res->first;
  PageNode *node = res->second;
  if (--(node->num_allocs) == 0) {
    PageNode *next = static_cast<PageNode *>(node->next);
    PageNode *prev = static_cast<PageNode *>(node->prev);
    if (prev) {
      prev->next = next;
    } else { // this was the first node
      __nodes = next;
    }
    if (next) {
      next->prev = prev;
    }

    delete[] page;
    delete node;
    __lookup.erase(res);
  }
}

AllocatorI *AllocatorI::create(AllocatorCategory C) {
  if (C == AllocatorCategory::PageAllocator) {
    return new PageAllocator();
  } else if (C == AllocatorCategory::ContiguousAllocator) {
    return new ContiguousAllocator();
  } else {
    return nullptr;
  }
}

} // end namespace oblivious
