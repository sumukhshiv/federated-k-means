//===------ __covert_o_impl.h - Implementation of Covert<O<...>,...> ------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __COVERT_O_IMPL_H__
#define __COVERT_O_IMPL_H__

#include "__covert_impl.h"
#include "cov_iterator.h"
#include "../Oblivious/O.h"

namespace covert {
namespace __covert_impl__ {

template <typename _CovertT, typename _AccessorT, auto _AccessorLabel,
          typename = void>
class __covert_accessor {
  friend class Covert_Pointer_Ops<_CovertT>;

  using __accessor_t = _AccessorT;
  using __covert_accessort_t =
      __covert_accessor<_CovertT, _AccessorT, _AccessorLabel>;
  using __label_type = decltype(_AccessorLabel);
  static constexpr __label_type __accessor_label = _AccessorLabel;
  using __lattice = Lattice<__label_type>;
  using __covert_traits = covert_traits<_CovertT>;
  using __iterator = typename __covert_traits::value_type;
  using __iterator_value_type =
      typename std::iterator_traits<__iterator>::value_type;
  static_assert(is_canonical_v<__label_type, __iterator_value_type>);
  using __iterator_value_type_labels =
      typename covert_traits<__iterator_value_type>::labels;
  static constexpr __label_type __iterator_value_type_label =
      covert_traits<__iterator_value_type>::label;
  static constexpr auto __iterator_value_type_num_labels =
      covert_traits<__iterator_value_type>::num_labels;
  using __iterator_value_type_value_type =
      typename covert_traits<__iterator_value_type>::value_type;

  __accessor_t __accessor;

  explicit __covert_accessor(
      const __accessor_t &accessor, const _CovertT &,
      std::integral_constant<__label_type, _AccessorLabel>)
      : __accessor(accessor) {}

public:
  using label_type = __label_type;
  static constexpr label_type label =
      __lattice::join(__iterator_value_type_label, __accessor_label);
  static constexpr auto num_labels = __iterator_value_type_num_labels;
  using labels = Append_t<ValueList<label_type, label>,
                          Tail_t<__iterator_value_type_labels>>;
  using value_type =
      ConstructCovert_t<__iterator_value_type_value_type, labels>;
  using reference = value_type &;
  using const_reference = const value_type &;

  template <
      typename _RetT,
      typename _CanonicalRetT = canonicalize_t<label_type, _RetT>,
      typename = std::enable_if_t<is_Covert_v<label_type, _CanonicalRetT>>,
      typename _ValueT = __iterator_value_type_value_type,
      typename _RetValueT = typename covert_traits<_CanonicalRetT>::value_type,
      typename =
          std::enable_if_t<is_covert_convertible_v<value_type, _CanonicalRetT>>,
      typename = std::enable_if_t<std::is_convertible_v<_ValueT, _RetValueT>>>
  inline operator _RetT() const {
    __COVERT_LOG_CAST__("Oblivious read", __iterator_value_type, _RetT);
    return static_cast<_RetT>(static_cast<__iterator_value_type>(__accessor));
  }
  template <typename _ArgT, typename _LatticeT = __lattice,
            typename _CanonicalArgT = canonicalize_t<__label_type, _ArgT>,
            typename = std::enable_if_t<
                _LatticeT::leq(__accessor_label, __iterator_value_type_label)>,
            typename = std::enable_if_t<
                is_covert_convertible_v<_CanonicalArgT, __iterator_value_type>>,
            typename = decltype(
                std::declval<__accessor_t>() = std::declval<const _ArgT &>())>
  inline __covert_accessort_t operator=(const _ArgT &val) const {
    __COVERT_LOG_CAST__("Oblivious write", _ArgT, __iterator_value_type);
    this->__accessor = val;
    return *this;
  }
};

template <typename _CovertT, typename _AccessorT, auto _L>
__covert_accessor(const _AccessorT &, const _CovertT &,
                  std::integral_constant<decltype(_L), _L>)
    -> __covert_accessor<_CovertT, _AccessorT, _L>;

/// \brief This class defines operations on low oblivious iterators.
///
/// These operations are optimized (with no overhead) by using unsafe reads
/// and writes.
template <typename _LabelT, typename _IterT, typename _ContainerT,
          _LabelT _Label>
class Covert_Pointer_Ops<
    Covert<_LabelT, oblivious::O<_IterT, _ContainerT>, _Label>> {
  using __ThisT = Covert<_LabelT, oblivious::O<_IterT, _ContainerT>, _Label>;
  using __traits = covert_traits<__ThisT>;
  using __label_type = typename __traits::label_type;
  using __value_type = typename __traits::value_type;
  using __difference_type = typename std::iterator_traits<
      oblivious::O<_IterT, _ContainerT>>::difference_type;
  using __labels = typename __traits::labels;
  static constexpr __label_type __label = __traits::label;
  template <typename, typename> friend struct canonicalize;

public:
  using reference = std::conditional_t<
      __label == Lattice<__label_type>::bottom,
      __covert_accessor<__ThisT,
                        decltype(
                            std::declval<oblivious::O<_IterT, _ContainerT> &>()
                                .__get_unsafe_accessor()),
                        __label>,
      __covert_accessor<
          __ThisT,
          decltype(*std::declval<oblivious::O<_IterT, _ContainerT> &>()),
          __label>>;

  template <
      typename _ArgT, typename _ValueT = __value_type,
      typename _CanonicalArgT = canonicalize_t<__label_type, _ArgT>,
      typename _ArgLabelT = typename covert_traits<_CanonicalArgT>::label_type,
      _ArgLabelT _ArgLabel = covert_traits<_CanonicalArgT>::label,
      typename _ArgValueT = typename covert_traits<_CanonicalArgT>::value_type,
      typename = std::enable_if_t<
          std::is_convertible_v<_ArgValueT, __difference_type>>,
      typename = decltype(
          std::declval<_ValueT &>()[std::declval<__difference_type>()])>
  inline auto operator[](_ArgT n) const {
    __COVERT_LOG2__(__ThisT, _ArgT, "Oblivious iterator subscript operator");
    constexpr __label_type access_label =
        Lattice<__label_type>::join(_ArgLabel, __label);
    auto _n = reinterpret_cast<_CanonicalArgT &>(n);
    const __ThisT &t = static_cast<const __ThisT &>(*this);
    if constexpr (access_label == Lattice<__label_type>::bottom) {
      return __covert_accessor{
          __covert_extract__(t).__get_unsafe_accessor(__covert_extract__(_n)),
          t, std::integral_constant<__label_type, access_label>{}};
    } else {
      return __covert_accessor{
          __covert_extract__(t)[__covert_extract__(_n)], t,
          std::integral_constant<__label_type, access_label>{}};
    }
  }

  inline auto operator*() const {
    __COVERT_LOG__(__ThisT, "Oblivious iterator dereference operator");
    const __ThisT &t = static_cast<const __ThisT &>(*this);
    if constexpr (__label == Lattice<__label_type>::bottom) {
      return __covert_accessor{__covert_extract__(t).__get_unsafe_accessor(), t,
                               std::integral_constant<__label_type, __label>{}};
    } else {
      return __covert_accessor{*__covert_extract__(t), t,
                               std::integral_constant<__label_type, __label>{}};
    }
  }
};

template <typename _CovertT, typename _Accessor, auto _AccessorLabel>
struct canonicalize<decltype(_AccessorLabel),
                    __covert_accessor<_CovertT, _Accessor, _AccessorLabel>> {
  using type = typename __covert_accessor<_CovertT, _Accessor,
                                          _AccessorLabel>::value_type;
};

template <typename _LabelT, typename _IterT, typename _ContainerT,
          _LabelT _Label>
class Covert_Base<Covert<_LabelT, oblivious::O<_IterT, _ContainerT>, _Label>> {
  using __ThisT = Covert<_LabelT, oblivious::O<_IterT, _ContainerT>, _Label>;
  using __traits = covert_traits<__ThisT>;
  using __label_type = typename __traits::label_type;
  using __value_type = typename __traits::value_type;
  using __reference = typename __traits::reference;
  using __const_reference = typename __traits::const_reference;
  using __labels = typename __traits::labels;

  __value_type __M_val__;

public:
  template <typename _T> friend class Covert_Base;
  friend constexpr __reference
  __covert_extract__(Covert_Base<__ThisT> &x) noexcept {
    return x.__M_val__;
  }
  friend constexpr __const_reference
  __covert_extract__(const Covert_Base<__ThisT> &x) noexcept {
    return x.__M_val__;
  }

  Covert_Base() = default;
  ~Covert_Base() = default;
  Covert_Base(const Covert_Base<__ThisT> &) = default;
  Covert_Base<__ThisT> &operator=(const Covert_Base<__ThisT> &) = default;

  __COVERT_CONSTEXPR__ Covert_Base(const _IterT &iter, _ContainerT *container)
      : __M_val__(iter, container) {
    __COVERT_LOG_CONSTRUCTOR__("O constructor", __ThisT, __value_type);
  }
  __COVERT_CONSTEXPR__ Covert_Base(const __value_type &x) : __M_val__(x) {
    __COVERT_LOG_CONSTRUCTOR__("O Converting constructor (primitive)", __ThisT,
                               __value_type);
  }
  template <
      typename _ArgIterT, __label_type _ArgLabel,
      typename _ArgValueT = oblivious::O<_ArgIterT, _ContainerT>,
      typename _ArgT = Covert<__label_type, _ArgValueT, _ArgLabel>,
      typename = std::enable_if_t<is_covert_convertible_v<_ArgT, __ThisT>>,
      typename =
          std::enable_if_t<std::is_constructible_v<__value_type, _ArgValueT>>>
  __COVERT_CONSTEXPR__ Covert_Base(
      const Covert_Base<
          Covert<__label_type, oblivious::O<_ArgIterT, _ContainerT>, _ArgLabel>>
          &x)
      : __M_val__(x.__M_val__) {
    __COVERT_LOG_CONSTRUCTOR__("O Converting constructor", __ThisT, _ArgT);
  }
};

template <typename _ThisT, typename _Enable = void> struct CovertO_check {
  using difference_type = void;
  using value_type = void;
  using pointer = void;
  using reference = void;
  using iterator_category = void;
};

template <typename _LabelT, typename _IterT, typename _ContainerT,
          _LabelT _Label>
struct CovertO_check<
    Covert<_LabelT, oblivious::O<_IterT, _ContainerT>, _Label>,
    std::enable_if_t<std::conjunction<
        std::disjunction<
            std::is_same<_IterT, typename _ContainerT::iterator>,
            std::is_same<_IterT, typename _ContainerT::const_iterator>>,
        is_canonical<_LabelT, typename std::iterator_traits<
                                  _IterT>::value_type>>::value>>
    : Covert_impl<Covert<_LabelT, oblivious::O<_IterT, _ContainerT>, _Label>> {
private:
  using __iterator = oblivious::O<_IterT, _ContainerT>;
  using __label_type = _LabelT;
  static constexpr __label_type __label = _Label;

public:
  using difference_type = covert::__covert_impl__::canonicalize_t<
      __label_type, typename std::iterator_traits<__iterator>::difference_type>;
  using value_type = covert::__covert_impl__::canonicalize_t<
      __label_type, typename std::iterator_traits<__iterator>::value_type>;
  using pointer = covert::__covert_impl__::canonicalize_t<
      __label_type,
      covert::Covert<__label_type,
                     typename std::iterator_traits<__iterator>::pointer,
                     __label>>;
  using reference = typename covert::__covert_impl__::Covert_Pointer_Ops<
      covert::Covert<__label_type, __iterator, __label>>::reference;
  using iterator_category =
      typename std::iterator_traits<__iterator>::iterator_category;

  using Covert_impl<
      Covert<_LabelT, oblivious::O<_IterT, _ContainerT>, _Label>>::Covert_impl;
};

} // end namespace __covert_impl__

template <typename LabelT, typename IterT, typename ContainerT, LabelT Label>
struct Covert<LabelT, oblivious::O<IterT, ContainerT>, Label>
    : __covert_impl__::CovertO_check<
          Covert<LabelT, oblivious::O<IterT, ContainerT>, Label>> {
private:
  using __ThisT = Covert<LabelT, oblivious::O<IterT, ContainerT>, Label>;
  using __base = __covert_impl__::CovertO_check<__ThisT>;

public:
  using difference_type = typename __base::difference_type;
  using value_type = typename __base::value_type;
  using pointer = typename __base::pointer;
  using reference = typename __base::reference;
  using iterator_category = typename __base::iterator_category;

  static_assert(
      std::is_same_v<IterT, typename ContainerT::iterator> ||
          std::is_same_v<IterT, typename ContainerT::const_iterator>,
      "IterT must either be the const or non-const iterator for ContainerT");
  static_assert(__covert_impl__::is_canonical_v<
                    LabelT, typename std::iterator_traits<IterT>::value_type>,
                "IterT's value_type must be in canonical form");
  using __covert_impl__::CovertO_check<__ThisT>::CovertO_check;
};

template <typename CovertT, typename AccessorT, auto AccessorLabel>
struct covert_traits<
    __covert_impl__::__covert_accessor<CovertT, AccessorT, AccessorLabel>> {
private:
  using __A =
      __covert_impl__::__covert_accessor<CovertT, AccessorT, AccessorLabel>;

public:
  using label_type = typename __A::label_type;
  static constexpr label_type label = __A::label;
  static constexpr auto num_labels = __A::num_labels;
  using labels = typename __A::labels;
  using value_type = typename __A::value_type;
  using reference = typename __A::reference;
  using const_reference = typename __A::const_reference;
};

} // end namespace covert

namespace std {
template <typename LabelT, typename IterT, typename ContainerT, LabelT Label>
struct iterator_traits<
    covert::Covert<LabelT, oblivious::O<IterT, ContainerT>, Label>> {
  using It = covert::Covert<LabelT, oblivious::O<IterT, ContainerT>, Label>;

  using difference_type = typename It::difference_type;
  using value_type = typename It::value_type;
  using pointer = typename It::pointer;
  using reference = typename It::reference;
  using iterator_category = typename It::iterator_category;
};
} // end namespace std

#endif
