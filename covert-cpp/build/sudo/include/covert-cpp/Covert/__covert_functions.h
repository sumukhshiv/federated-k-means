//===- __covert_functions.h - Defines casting functions, etc. for Covert --===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __COVERT_FUNCTIONS_H__
#define __COVERT_FUNCTIONS_H__

#define COVERT_TO_PRIMITIVE(prefix, label)                                     \
  template <__COVERT_LABEL_DECL__ typename _ArgT,                              \
            typename _CanonicalArgT = covert::__covert_impl__::canonicalize_t< \
                __COVERT_LABEL__(label), _ArgT>,                               \
            typename _ArgValueT =                                              \
                typename covert::covert_traits<_CanonicalArgT>::value_type>    \
  __COVERT_CONSTEXPR__ _ArgValueT prefix##_to_primitive(_ArgT &&x) noexcept {  \
    using namespace covert;                                                    \
    using namespace covert::__covert_impl__;                                   \
    __COVERT_LOG_CAST__(#prefix "_to_primitive", _ArgT, _ArgValueT);           \
                                                                               \
    if constexpr (is_primitive_v<__COVERT_LABEL__(label), _ArgT>) {            \
      return x;                                                                \
    } else if constexpr (is_canonical_v<__COVERT_LABEL__(label), _ArgT>) {     \
      return __covert_extract__(x);                                            \
    } else {                                                                   \
      return reinterpret_cast<_ArgValueT &&>(x);                               \
    }                                                                          \
  }

namespace covert {
// FIXME: Make this function useful!
template <typename _RT, typename... _ArgTs>
inline auto fp_cast(__covert_impl__::fptr<_RT, _ArgTs...> f) {
  using namespace __covert_impl__;
#ifdef __LOG_COVERT_CPP__
  using ArgT = fptr<_RT, _ArgTs...>;
#endif
  using RetT = fptr<Unwrap_t<_RT>, Unwrap_t<_ArgTs>...>;
  __COVERT_LOG_CAST__("fp_cast", ArgT, RetT);
  return reinterpret_cast<RetT>(f);
}
} // end namespace covert

#define COVERT_LABEL_CAST(prefix, label)                                       \
  template <__COVERT_LABEL_DECL__ typename _RetValueT,                         \
            __COVERT_LABEL__(label)... _RetLs, typename _ArgT,                 \
            typename _CanonicalArgT = covert::__covert_impl__::canonicalize_t< \
                __COVERT_LABEL__(label), _ArgT>,                               \
            typename _traits = covert::covert_traits<_CanonicalArgT>,          \
            typename _ArgValueT = typename _traits::value_type,                \
            typename _RetT = covert::__covert_impl__::ConstructCovert_t<       \
                _RetValueT, covert::__covert_impl__::ValueList<                \
                                __COVERT_LABEL__(label), _RetLs...>>,          \
            typename = std::enable_if_t<!std::is_void_v<_RetT>>,               \
            typename = std::enable_if_t<                                       \
                std::is_convertible_v<_ArgValueT, _RetValueT>>>                \
  __COVERT_CONSTEXPR__ _RetT prefix##_label_cast(_ArgT &&x) noexcept {         \
    using namespace covert;                                                    \
    using namespace covert::__covert_impl__;                                   \
    __COVERT_LOG_CAST__(#prefix "_label_cast", _ArgT, _RetT);                  \
                                                                               \
    using Cast =                                                               \
        std::conditional_t<std::is_lvalue_reference<_RetT>::value,             \
                           _reinterpret_cast<_RetT>, _static_cast<_RetT>>;     \
    return Cast{}(                                                             \
        __covert_extract__(make_canonical<__COVERT_LABEL__(label)>(x)));       \
  }

#define COVERT_NAMED_CAST(prefix, label, named_cast)                           \
  template <                                                                   \
      __COVERT_LABEL_DECL__ typename _RetValueT,                               \
      __COVERT_LABEL__(label)... _RetLs, typename _ArgT,                       \
      typename _CanonicalArgT = covert::__covert_impl__::canonicalize_t<       \
          __COVERT_LABEL__(label), _ArgT>,                                     \
      typename _traits_ArgT = covert::covert_traits<_CanonicalArgT>,           \
      typename _RetT = covert::__covert_impl__::ConstructCovert_t<             \
          _RetValueT, covert::__covert_impl__::ValueList<                      \
                          __COVERT_LABEL__(label), _RetLs...>>,                \
      typename = std::enable_if_t<!std::is_void_v<_RetT>>,                     \
      typename _ArgValueT = typename _traits_ArgT::value_type,                 \
      typename = decltype(named_cast<_RetValueT>(std::declval<_ArgValueT>())), \
      typename _CanonicalRetT = covert::__covert_impl__::canonicalize_t<       \
          __COVERT_LABEL__(label), _RetT>,                                     \
      typename =                                                               \
          std::enable_if_t<covert::__covert_impl__::is_covert_convertible_v<   \
              _CanonicalArgT, _CanonicalRetT>>>                                \
  __COVERT_CONSTEXPR__ _RetT prefix##_##named_cast(_ArgT &&x) noexcept {       \
    using namespace covert;                                                    \
    using namespace covert::__covert_impl__;                                   \
    __COVERT_LOG_CAST__(#prefix "_" #named_cast, _ArgT, _RetT);                \
                                                                               \
    using RetCast =                                                            \
        std::conditional_t<std::is_reference<_RetT>::value,                    \
                           _reinterpret_cast<_RetT>, _static_cast<_RetT>>;     \
    return RetCast{}(named_cast<_RetValueT>(                                   \
        __covert_extract__(make_canonical<__COVERT_LABEL__(label)>(x))));      \
  }

/*******************************************************************************
 * Covert Guard
 ******************************************************************************/

#define COVERT_GUARD(prefix, label)                                            \
  template <__COVERT_LABEL_DECL__ __COVERT_LABEL__(label) _L,                  \
            __COVERT_LABEL__(label)... _Ls, typename _ArgT,                    \
            typename _Lst = covert::__covert_impl__::ValueList<                \
                __COVERT_LABEL__(label), _L, _Ls...>,                          \
            typename _CanonicalArgT = covert::__covert_impl__::canonicalize_t< \
                __COVERT_LABEL__(label), _ArgT>,                               \
            typename _traits = covert::covert_traits<_CanonicalArgT>,          \
            typename = std::enable_if_t<covert::__covert_impl__::Increasing_v< \
                covert::__covert_impl__::Zip_t<                                \
                    typename _traits::labels,                                  \
                    covert::__covert_impl__::ValueList<                        \
                        __COVERT_LABEL__(label), _L, _Ls...>>>>>               \
  __COVERT_CONSTEXPR__ _ArgT prefix##_guard(_ArgT &&x) noexcept {              \
    __COVERT_LOG_GUARD__(prefix, _Lst, _ArgT);                                 \
    return x;                                                                  \
  }

#define __GENERATE_COVERT_FUNCTIONS__(prefix, label)                           \
  COVERT_TO_PRIMITIVE(prefix, label);                                          \
  COVERT_GUARD(prefix, label);                                                 \
  COVERT_LABEL_CAST(prefix, label);                                            \
  COVERT_NAMED_CAST(prefix, label, static_cast);                               \
  COVERT_NAMED_CAST(prefix, label, reinterpret_cast);                          \
  COVERT_NAMED_CAST(prefix, label, const_cast);                                \
  COVERT_NAMED_CAST(prefix, label, dynamic_cast);

#define __COVERT_LABEL_DECL__ typename _LabelT,
#define __COVERT_LABEL__() _LabelT
GENERATE_COVERT_FUNCTIONS(covert, )

#undef __COVERT_LABEL_DECL__
#undef __COVERT_LABEL__
#define __COVERT_LABEL_DECL__
#define __COVERT_LABEL__(label) label

#endif
