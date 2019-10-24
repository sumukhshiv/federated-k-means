//===---------- O.h - The O template (oblivious iterator/pointer) ---------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_O_H__
#define __OBLIVIOUS_O_H__

#include <iterator>

/**
 * \ingroup OBLIVIOUS
 * \brief Defines a C++ template library interface to oblivious containers and
 * algorithms.
 *
 * The C++ interface to libOblivious exports template types and functions to
 * facilitate oblivious application design. The library exports three kinds of
 * components:
 * - **Oblivious sequence containers**: These containers such as ovector and
 *   olist wrap their non-oblivious STL counterparts. They use a custom heap
 *   allocator to manage memory in a way which allows it to be accessed
 *   obliviously.
 * - **Oblivious algorithms**: Oblivious implementations of the algorithms
 *   defined in the C++ STL algorithms library, and which operate over
 *   oblivious containers.
 * - **Oblivious iterators**: A wrapper around a pointer or iterator which can
 *   be used to obliviously read from or write to memory allocated by oblivious
 *   containers.
 *
 * The following example illustrates the three components being used in tandem:
 * \code
 * using namespace oblivious;
 * using ListT = oforward_list<unsigned int>;
 * using IterT = typename ListT::const_iterator;
 *
 * // return the first value less than `x` in `list`, or -1 if there is no such
 * // value
 * int find_less_than(const ListT &list, int x) {
 *   auto finder = [x](int val) { return val < x; };
 *   O<IterT, const ListT> i =
 *       ofind_if(list.begin(), list.end(), finder, &list);
 *   if (i == list.end()) // value less than `x` not found
 *     return -1;
 *   else // return the value we found
 *     return *i;
 * }
 * \endcode
 *
 * In this example, `list` is an oblivious forward (i.e. singly-linked) list,
 * which means that it uses the libOblivious heap allocator. The ofind_if
 * algorithm scans the entire container and examines each element, regardless
 * of whether an element satisfying `finder` has already been found. Once the
 * container has been entirely scanned, an `O` iterator to the first element
 * satisfying `finder` is returned, and stored in `i`. Assuming that a match
 * was found, `i` is dereferenced (read from) and the result is returned to the
 * caller.
 *
 * Under the hood, the dereference (`*`) operation on oblivious iterators is
 * complex. In brief, it queries the oblivious container's allocator to obtain
 * a list of all the memory regions that have been allocated by the container.
 * During a read, the oblivious iterator invokes o_read_list_T(), and on a write
 * it invokes o_write_list_T(). For more detailed information, see the
 * \ref OBLIVIOUS C interface documentation regarding oblivious reads and
 * writes.
 */
namespace oblivious {

/**
 * \brief An oblivious iterator.
 *
 * The O template wraps an iterator (possibly a pointer) to an oblivious
 * container, e.g. a container with an "o" prefix. An object of type `O<T, CT>`
 * can do anything that an object of type `T` can do, except for the `->` arrow
 * member access operator. This is because `O<T, CT>` can only be used to read
 * from or write to the value referenced by the wrapped iterator (or pointer).
 * The correct way to access members is to first make a copy, e.g. on the stack
 * as follows:
 * \code
 * int foo(O<const my_struct *, my_struct[1024]> o) {
 *   // equivalent to
 *   // return o[42].member_int1 + o[42].member_int2;
 *   my_struct val = o[42];
 *   return val.member_int1 + val.member_int2;
 * }
 * \endcode
 * And to update a member:
 * \code
 * int foo(O<my_struct *, my_struct[1024]> o) {
 *   // equivalent to
 *   // o[42].member_int1 += 11;
 *   my_struct val = o[42];
 *   val.member_int1 += 11;
 *   o[42] = val;
 * }
 * \endcode
 *
 * \tparam IterT Must be one of `ContainerT::iterator` or
 *         `ContainerT::const_iterator`.
 * \tparam ContainerT The type of the container being iterated over. Must either
 *         be a container satisfying the `AllocatorAwareContainer` concept and
 *         using the oblivious::oallocator, or a container using a fixed amount
 *         of contiguous storage (e.g. an array-like container) and satisfying
 *         the `Container` concept.
 */
template <typename IterT, typename ContainerT> struct O;

} // namespace oblivious

#include "__o_impl.h"

namespace oblivious {

template <typename IterT, typename ContainerT>
struct O : __oblivious_impl::__o<IterT, ContainerT> {
  using difference_type =
      typename __oblivious_impl::__o<IterT, ContainerT>::difference_type;
  using value_type =
      typename __oblivious_impl::__o<IterT, ContainerT>::value_type;
  using pointer = typename __oblivious_impl::__o<IterT, ContainerT>::pointer;
  using reference =
      typename __oblivious_impl::__o<IterT, ContainerT>::reference;
  using iterator_category =
      typename __oblivious_impl::__o<IterT, ContainerT>::iterator_category;

  using __oblivious_impl::__o<IterT, ContainerT>::__o;
};

template <typename T, std::size_t N>
struct O<T *, T[N]> : __oblivious_impl::__o<T *, T[N]> {
  using difference_type =
      typename __oblivious_impl::__o<T *, T[N]>::difference_type;
  using value_type = typename __oblivious_impl::__o<T *, T[N]>::value_type;
  using pointer = typename __oblivious_impl::__o<T *, T[N]>::pointer;
  using reference = typename __oblivious_impl::__o<T *, T[N]>::reference;
  using iterator_category =
      typename __oblivious_impl::__o<T *, T[N]>::iterator_category;

  using __oblivious_impl::__o<T *, T[N]>::__o;
};

template <typename T, std::size_t N>
struct O<const T *, T[N]> : __oblivious_impl::__o<const T *, T[N]> {
  using difference_type =
      typename __oblivious_impl::__o<const T *, T[N]>::difference_type;
  using value_type =
      typename __oblivious_impl::__o<const T *, T[N]>::value_type;
  using pointer = typename __oblivious_impl::__o<const T *, T[N]>::pointer;
  using reference = typename __oblivious_impl::__o<const T *, T[N]>::reference;
  using iterator_category =
      typename __oblivious_impl::__o<const T *, T[N]>::iterator_category;

  using __oblivious_impl::__o<const T *, T[N]>::__o;
};

template <typename T, std::size_t N>
struct O<const T *, const T[N]> : __oblivious_impl::__o<const T *, const T[N]> {
  using difference_type =
      typename __oblivious_impl::__o<const T *, const T[N]>::difference_type;
  using value_type =
      typename __oblivious_impl::__o<const T *, const T[N]>::value_type;
  using pointer =
      typename __oblivious_impl::__o<const T *, const T[N]>::pointer;
  using reference =
      typename __oblivious_impl::__o<const T *, const T[N]>::reference;
  using iterator_category =
      typename __oblivious_impl::__o<const T *, const T[N]>::iterator_category;

  using __oblivious_impl::__o<const T *, const T[N]>::__o;
};

template <typename IterT, typename ContainerT>
O(const IterT &, ContainerT *)->O<IterT, ContainerT>;

} // end namespace oblivious

#endif
