//===- cov_iterator.h - iterator_traits for Covert iterators and pointers -===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __COVERT_ITERATOR_H__
#define __COVERT_ITERATOR_H__

#include "Covert.h"
#include <iterator>

namespace std {
template <typename LabelT, typename It, LabelT Label>
struct iterator_traits<covert::Covert<LabelT, It, Label>> {
  using difference_type = covert::__covert_impl__::canonicalize_t<
      LabelT, typename std::iterator_traits<It>::difference_type>;
  using value_type = covert::__covert_impl__::canonicalize_t<
      LabelT, typename std::iterator_traits<It>::value_type>;
  using pointer = covert::__covert_impl__::canonicalize_t<
      LabelT, covert::Covert<LabelT, typename std::iterator_traits<It>::pointer,
                             Label>>;
  using reference = covert::__covert_impl__::canonicalize_t<
      LabelT, typename std::iterator_traits<It>::reference>;
  using iterator_category =
      typename std::iterator_traits<It>::iterator_category;
};
} // end namespace std

#endif
