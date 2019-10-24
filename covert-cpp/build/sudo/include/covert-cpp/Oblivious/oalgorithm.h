//===----------- oalgorithm.h - libOblivious algorithms library -----------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_OALGORITHM_H__
#define __OBLIVIOUS_OALGORITHM_H__

#include "O.h"

namespace oblivious {

/**
 * \brief Obliviously sorts the elements in the range [first, last) in
 * ascending order.
 *
 * The order of equal elements is not guaranteed to be preserved. The time
 * complexity is *O(n^2)*.
 *
 * \param first The first element in the range to sort.
 * \param last Past-the-last element in the range to sort.
 * \param comp Comparison function object. The signature should be equivalent
 *        to the following:
 *        \code
 *        bool cmp(const Type1 &a, const Type2 &a);
 *        \endcode
 */
template <class RandomIt, class Compare>
void osort(RandomIt first, RandomIt last, Compare comp) {
  for (std::size_t n = last - first; n > 0; --n) {
    for (std::size_t i = 1; i < n; ++i) {
      o_swap_T(comp(first[i], first[i - 1]), first[i - 1], first[i]);
    }
  }
}

/**
 * \brief Obliviously sorts the elements in the range [first, last) in
 * ascending order using `operator<`.
 *
 * The order of equal elements is not guaranteed to be preserved. The time
 * complexity is *O(n^2)*.
 *
 * \param first The first element in the range to sort.
 * \param last Past-the-last element in the range to sort.
 */
template <class RandomIt> void osort(RandomIt first, RandomIt last) {
  using const_reference =
      const typename std::iterator_traits<RandomIt>::value_type &;
  osort(first, last,
        [](const_reference v1, const_reference v2) { return v1 < v2; });
}

/**
 * \brief Obliviously locate the greatest element in the range
 * [\p first, \p last).
 *
 * The time complexity is *O(n)*.
 *
 * \param first The first element in the range to search.
 * \param last Past-the-last element in the range to search.
 * \param comp Comparison function object. The signature should be equivalent
 *        to the following:
 *        \code
 *        bool cmp(const Type1 &a, const Type2 &a);
 *        \endcode
 * \param container Pointer to the container over which \p first and \p last
 *        are defined.
 * \return Oblivious iterator to the greatest element in the range
 *         [\p first, \p last). If several elements in the range are equivalent
 *         to the greatest element, return the iterator to the first such
 *         element.
 */
template <class ForwardIt, class Compare, class ContainerT>
O<ForwardIt, ContainerT> omax_element(ForwardIt first, ForwardIt last,
                                     Compare comp, ContainerT *container) {
  if (first == last) {
    return {last, container};
  }

  using value_type = typename std::iterator_traits<ForwardIt>::value_type;
  ForwardIt largest = first;
  value_type largest_val = *largest;
  ++first;
  for (; first != last; ++first) {
    value_type val = *first;
    bool new_largest = comp(largest_val, val);
    o_copy_T(largest_val, new_largest, val, largest_val);
    o_copy_T(largest, new_largest, first, largest);
  }
  return {largest, container};
}

/**
 * \brief Obliviously locate the greatest element in the range
 * [\p first, \p last) using `operator<`.
 *
 * The time complexity is *O(n)*.
 *
 * \param first The first element in the range to search.
 * \param last Past-the-last element in the range to search.
 * \param container Pointer to the container over which \p first and \p last
 *        are defined.
 * \return Oblivious iterator to the greatest element in the range
 *         [\p first, \p last). If several elements in the range are equivalent
 *         to the greatest element, return the iterator to the first such
 *         element.
 */
template <class ForwardIt, class ContainerT>
O<ForwardIt, ContainerT> omax_element(ForwardIt first, ForwardIt last,
                                     ContainerT *container) {
  using value_type = typename std::iterator_traits<ForwardIt>::value_type;
  return omax_element(
      first, last,
      [](const value_type &x, const value_type &y) { return x < y; },
      container);
}

/**
 * \brief Searches for an element for which predicate \p p returns \c true.
 *
 * \param first The first element to examine.
 * \param last Past-the-last element to examine.
 * \param p Predicate function of type `bool(typename InputIt::value_type)`.
 * \param container Pointer to the container over which \p first and \p last
 *        are defined.
 * \return An oblivious iterator pointing to the first element which satisfies
 *         \p p. If not element satisifes \p p, an oblivious iterator equal to
 *         \p last is returned.
 */
template <class InputIt, class UnaryPredicate, class ContainerT>
O<InputIt, ContainerT> ofind_if(InputIt first, InputIt last, UnaryPredicate p,
                                ContainerT *container) {
  InputIt ret = last;
  for (; first != last; ++first) {
    o_copy_T(ret, p(*first) & (ret == last), first, ret);
  }
  return {ret, container};
}

/**
 * \brief Searches for an element with a given value.
 *
 * \param first The first element to examine.
 * \param last Past-the-last element to examine.
 * \param value Value to which to compare the elements.
 * \param container Pointer to the container over which \p first and \p last
 *        are defined.
 * \return An oblivious iterator pointing to the first element which equals
 *         \p value. If not element equals \p value, an oblivious iterator equal
 * to \p last is returned.
 */
template <class InputIt, class T, class ContainerT>
O<InputIt, ContainerT> ofind(InputIt first, InputIt last, const T &value,
                             ContainerT *container) {
  return ofind_if(first, last, [&value](const T &x) { return value == x; },
                  container);
}

} // end namespace oblivious

#endif
