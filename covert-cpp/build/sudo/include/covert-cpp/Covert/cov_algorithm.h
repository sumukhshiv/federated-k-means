//===----------- cov_algorithm.h - Covert C++ algorithms library  ---------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

////////////////////////////////////////////////////////////////////////////////
// cov_algorithm.h
////////////////////////////////////////////////////////////////////////////////

#ifndef __COVERT_ALGORITHM_H__
#define __COVERT_ALGORITHM_H__

#include <algorithm>
#include "../Oblivious/oalgorithm.h"
#include "cov_iterator.h"
#include "CovertO.h"

namespace covert {

template <typename CondT, typename LabelT, typename T, LabelT L, LabelT R>
auto ternary(CondT c, const Covert<LabelT, T, L> &left,
             const Covert<LabelT, T, R> &right) {
  using __lattice = Lattice<LabelT>;
  auto cond =
      static_cast<__covert_impl__::canonicalize_t<LabelT, CondT>>(c);
  constexpr LabelT __cond_label = covert_traits<decltype(cond)>::label;
  Covert<LabelT, T, __lattice::join(__cond_label, __lattice::join(L, R))> ret;

  if constexpr (__cond_label != __lattice::bottom) {
    T &_ret = covert_to_primitive<LabelT>(ret);
    const T &_left = covert_to_primitive<LabelT>(left);
    const T &_right = covert_to_primitive<LabelT>(right);
    bool _cond = covert_to_primitive<LabelT>(cond);
    o_copy_T(_ret, _cond, _left, _right);
  } else {
    ret = cond ? left : right;
  }

  return ret;
}

template <typename It, typename F> void visit(It I, It E, F &f) {
  using ResultT = decltype(f(I));
  using ResultTraits = covert_traits<ResultT>;
  using LabelType = typename ResultTraits::label_type;

  for (; I != E; ++I) {
    if constexpr (ResultTraits::label == Lattice<LabelType>::bottom) {
      if (f(I))
        return;
    } else {
      (void)f(I);
    }
  }
}

template <class InputIt, class UnaryPredicate>
auto find_if(InputIt I, InputIt E, UnaryPredicate P) {
  using LabelT = typename covert_traits<InputIt>::label_type;
  using IterT = typename covert_traits<InputIt>::value_type;
  constexpr LabelT RetL = covert_traits<decltype(P(*I))>::label;

  auto ret = covert_label_cast<LabelT, IterT, RetL>(E);
  auto f = [&](auto x) {
    auto found = ret != E;
    ret =
        ternary(covert_static_cast<LabelT, bool, RetL>(P(*x) & !found), x, ret);
    return found;
  };
  visit(I, E, f);
  return ret;
}

template <class InputIt, class T>
auto find(InputIt I, InputIt E, const T &value) {
  return covert::find_if(I, E, [&value](const auto &v) { return v == value; });
}

template <class InputIt, class UnaryPredicate>
auto find_if_not(InputIt I, InputIt E, UnaryPredicate P) {
  return covert::find_if(I, E, [&P](const auto &v) { return !P(v); });
}

template <class InputIt, class UnaryPredicate>
auto all_of(InputIt I, InputIt E, UnaryPredicate P) {
  return covert::find_if_not(I, E, P) == E;
}

template <class InputIt, class UnaryPredicate>
auto any_of(InputIt I, InputIt E, UnaryPredicate P) {
  return covert::find_if(I, E, P) != E;
}

template <class InputIt, class UnaryPredicate>
auto none_of(InputIt I, InputIt E, UnaryPredicate P) {
  return covert::find_if(I, E, P) == E;
}

template <class RandomIt, class Compare>
void sort(RandomIt first, RandomIt last, Compare comp) {
  using label_type =
      typename covert_traits<decltype(comp(*first, *first))>::label_type;
  constexpr auto value_label =
      covert_traits<decltype(comp(*first, *first))>::label;
  if constexpr (value_label == Lattice<label_type>::bottom) {
    std::sort(first, last, comp);
  } else {
    oblivious::osort(first, last, [comp](const auto &x, const auto &y) {
      return covert_label_cast<label_type, bool, Lattice<label_type>::bottom>(
          comp(x, y));
    });
  }
}

template <class RandomIt> void sort(RandomIt first, RandomIt last) {
  covert::sort(first, last, [](const auto &x, const auto &y) { return x < y; });
}

template <class ForwardIt, class Compare, class ContainerT>
auto max_element(ForwardIt first, ForwardIt last, Compare comp,
                 ContainerT *container) {
  using label_type =
      typename covert_traits<decltype(comp(*first, *first))>::label_type;
  constexpr auto value_label =
      covert_traits<decltype(comp(*first, *first))>::label;
  using RetT =
      Covert<label_type, oblivious::O<ForwardIt, ContainerT>, value_label>;
  if constexpr (value_label == Lattice<label_type>::bottom) {
    return RetT{std::max_element(first, last, comp), container};
  } else {
    return RetT{oblivious::omax_element(
        first, last,
        [comp](const auto &x, const auto &y) {
          return covert_label_cast<label_type, bool,
                                   Lattice<label_type>::bottom>(comp(x, y));
        },
        container)};
  }
}

template <class ForwardIt, class ContainerT>
auto max_element(ForwardIt first, ForwardIt last, ContainerT *container) {
  return covert::max_element(first, last,
                             [](const auto &x, const auto &y) { return x < y; },
                             container);
}

} // end namespace covert

#endif
