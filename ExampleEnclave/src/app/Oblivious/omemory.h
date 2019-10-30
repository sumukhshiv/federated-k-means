//===-------------- omemory.h - libOblivious heap allocators  -------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_OMEMORY_H__
#define __OBLIVIOUS_OMEMORY_H__

#include "Oblivious.h"
#include <memory>

#ifdef __LOG_LIB_OBLIVIOUS__
#include <iostream>
#define LOG(msg)                                                               \
  { std::cout << msg << std::endl; }
#else
#define LOG(msg)
#endif

namespace oblivious {

/**
 * \details
 * The PageAllocator oblivious allocator is generic, and thus can be used with
 * any container.
 *
 * The ContiguousAllocator oblivious allocator is optimized for containers with
 * dynamic, contiguous storage, e.g. a container which satisfies the
 * ContiguousContainer concept. This allocator can only track one memory region
 * at a time.
 */
enum class AllocatorCategory {
  PageAllocator,
  ContiguousAllocator,
};

/**
 * \brief Interface for implementing oblivous memory allocators.
 *
 * Oblivious memory allocators should be agnostic to the type of object(s) being
 * allocated. This is because the oallocator which uses this interface can be
 * rebound to a different type. Hence the object size must be passed to each
 * allocate() and deallocate() call.
 */
struct AllocatorI {
  EXPORT static AllocatorI *create(AllocatorCategory C);

  virtual ~AllocatorI() {}
  virtual void dump_state() const {}
  virtual std::size_t size() const = 0;
  virtual const o_mem_node *get_regions() const = 0;
  virtual void *allocate(std::size_t n, std::size_t object_size,
                         std::size_t align) = 0;
  virtual void deallocate(void *p, std::size_t n, std::size_t object_size) = 0;
};

/**
 * \brief The oblivious allocator.
 *
 * This allocator is stateful. It maintains a (possibly empty) linked list of
 * contiguous memory regions that have been created by calls to allocate(). The
 * allocated regions are all aligned to the CPU cache block size, which enables
 * better optimization for oblivious memory accesses.
 *
 * Satisfies the Allocator concept.
 */
template <typename T, AllocatorCategory C = AllocatorCategory::PageAllocator>
class oallocator {
  template <typename, AllocatorCategory> friend class oallocator;

  std::shared_ptr<AllocatorI> __impl;

public:
  using value_type = T;
  using is_always_equal = std::false_type;
  using propagate_on_container_copy_assignment = std::false_type;
  using propagate_on_container_move_assignment = std::true_type;
  using propagate_on_container_swap = std::true_type;
  template <typename U> struct rebind { using other = oallocator<U, C>; };

  static_assert(alignof(value_type) <= BLOCK_SIZE, "");

  oallocator() : __impl(AllocatorI::create(C)) {
    LOG("oallocator default constructor");
  }
  oallocator(const oallocator &other) noexcept : __impl(other.__impl) {
    LOG("oallocator copy constructor");
  }
  template <typename U>
  oallocator(const oallocator<U, C> &other) noexcept : __impl(other.__impl) {
    LOG("oallocator template copy constructor");
  }
  oallocator(oallocator &&other) noexcept : __impl(other.__impl) {
    LOG("oallocator move constructor");
  }
  oallocator &operator=(const oallocator &other) {
    LOG("oallocator copy assignment");
    __impl = other.__impl;
    return *this;
  }
  oallocator &operator=(oallocator &&other) {
    LOG("oallocator move assignment");
    __impl = other.__impl;
    return *this;
  }

  oallocator<T, C> select_on_container_copy_construction() const {
    LOG("oallocator select_on_container_copy_construction");
    return {};
  }

  void dump_state() const { __impl->dump_state(); }

  /**
   * \brief Return the total number of bytes allocated.
   */
  std::size_t size() const { return __impl->size(); }

  /**
   * \brief Returns the internal state of the allocator.
   *
   * Can be used to access allocated memory obliviously, e.g. using the
   * `oread_list*()` and `owrite_list*()` APIs.
   */
  const o_mem_node *get_regions() const { return __impl->get_regions(); }

  value_type *allocate(std::size_t n, const void * = 0) {
    return static_cast<value_type *>(
        __impl->allocate(n, sizeof(value_type), alignof(value_type)));
  }

  void deallocate(value_type *p, std::size_t n) {
    __impl->deallocate(p, n, sizeof(value_type));
  }

  /**
   * \brief Returns \c true if and only if \p a2 can deallocate storage that
   * was allocated through \p a1.
   *
   * That is, two allocators are equivalent if one is a copy of the other (and
   * thus they share the same memory regions), or they are both empty.
   */
  template <typename T2> bool operator==(const oallocator<T2, C> &a2) const {
    return (this->__impl == a2.__impl) ||
           (!this->__impl->get_regions() && !a2.__impl->get_regions());
  }

  /**
   * \brief Returns \c true if and only if \p a2 is not equivalent to \p a1.
   */
  template <typename T2> bool operator!=(const oallocator<T2, C> &a2) const {
    return !(*this == a2);
  }
};

template <typename T> struct is_oallocator : std::false_type {};
template <typename T, AllocatorCategory C>
struct is_oallocator<oallocator<T, C>> : std::true_type {};

} // namespace oblivious

#undef LOG

#endif
