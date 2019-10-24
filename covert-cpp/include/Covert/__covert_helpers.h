//===------ __covert_helpers.h - Metafunctions to assist Covert C++ -------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __COVERT_HELPERS_H__
#define __COVERT_HELPERS_H__

#include <type_traits>

namespace covert {
namespace __covert_impl__ {

#ifdef __LOG_COVERT_CPP__
#define __COVERT_CONSTEXPR__ inline
#define __COVERT_ASSERT__(x)                                                   \
  if (!(x)) {                                                                  \
    *logd << "Assertion failed: " #x "\n";                                     \
    return -1;                                                                 \
  }
#define __COVERT_LOG__(T, msg)                                                 \
  {                                                                            \
    using namespace covert::__covert_logging__;                                \
    if (logd)                                                                  \
      *logd << TypePrinter<T>::print_type << ": " << msg << '\n';              \
  }
#define __COVERT_LOG2__(T1, T2, msg)                                           \
  {                                                                            \
    using namespace covert::__covert_logging__;                                \
    if (logd)                                                                  \
      *logd << TypePrinter<T1>::print_type << ", "                             \
            << TypePrinter<T2>::print_type << ": " << msg << '\n';             \
  }
#define __COVERT_LOG_CAST__(msg, T1, T2)                                       \
  {                                                                            \
    using namespace covert::__covert_logging__;                                \
    if (logd)                                                                  \
      *logd << msg << ": '" << TypePrinter<T1>::print_type << "' -> '"         \
            << TypePrinter<T2>::print_type << "'\n";                           \
  }
#define __COVERT_LOG_CONSTRUCTOR__(msg, T, ...)                                \
  {                                                                            \
    using namespace covert::__covert_logging__;                                \
    if (logd)                                                                  \
      *logd << msg << ": '" << TypePrinter<T>::print_type << "("               \
            << TypePrinter<__VA_ARGS__>::print_type << ")'\n";                 \
  }
#define __COVERT_LOG_GUARD__(prefix, labels, T)                                \
  {                                                                            \
    using namespace covert::__covert_logging__;                                \
    if (logd) {                                                                \
      *logd << #prefix "_guard<" << LabelListPrinter<labels>::print_labels     \
            << ">: '" << TypePrinter<T>::print_type << "'\n";                  \
    }                                                                          \
  }
#define TEST(...)                                                              \
  {                                                                            \
    using namespace covert::__covert_logging__;                                \
    *logd << "\nTEST: " << #__VA_ARGS__ << '\n';                               \
    { __VA_ARGS__; };                                                          \
    *logd << "END TEST\n";                                                     \
  }
#else
#define __COVERT_CONSTEXPR__ constexpr
#define __COVERT_ASSERT__(x)
#define __COVERT_LOG__(T, msg)
#define __COVERT_LOG2__(T1, T2, msg)
#define __COVERT_LOG_CAST__(msg, T1, T2)
#define __COVERT_LOG_CONSTRUCTOR__(msg, T, ...)
#define __COVERT_LOG_GUARD__(prefix, labels, T)
#endif

/*******************************************************************************
 * Utility Metafunctions
 ******************************************************************************/

// Checks whether T is a function pointer
template <typename _T>
struct is_function_pointer
    : std::bool_constant<std::is_pointer_v<_T> &&
                         std::is_function_v<std::remove_pointer_t<_T>>> {};
template <typename _T>
constexpr bool is_function_pointer_v = is_function_pointer<_T>::value;

template <typename _T> struct _static_cast {
  template <typename _U> constexpr _T operator()(_U &&x) {
    return static_cast<_T>(x);
  }
};
template <typename _T> struct _reinterpret_cast {
  template <typename _U> inline _T operator()(_U &&x) {
    return reinterpret_cast<_T>(x);
  }
};

///////////////////////
// TypePair, TypeList

template <typename _T1, typename _T2> struct TypePair {
  using first_type = _T1;
  using second_type = _T2;
};
template <typename... _Ts> struct TypeList {};

///////////////////////
// ValuePair, ValueList

template <typename _ValueT, _ValueT... _Xs> struct ValueList {
  using value_type = _ValueT;
};
template <typename _ValueT, _ValueT _X1, _ValueT _X2> struct ValuePair {
  using value_type = _ValueT;
  static constexpr value_type first = _X1;
  static constexpr value_type second = _X2;
};

///////////////////////
// List Operations

template <typename _LstT> struct Head;
template <typename _ValueT, _ValueT _L, _ValueT... _Ls>
struct Head<ValueList<_ValueT, _L, _Ls...>> {
  static constexpr _ValueT value = _L;
};
template <typename _LstT> constexpr auto Head_v = Head<_LstT>::value;
template <typename _LstT> struct Tail;
template <typename _ValueT, _ValueT _L, _ValueT... _Ls>
struct Tail<ValueList<_ValueT, _L, _Ls...>> {
  using type = ValueList<_ValueT, _Ls...>;
};
template <typename _LstT> using Tail_t = typename Tail<_LstT>::type;

template <unsigned _N, typename _LstT1, typename _LstT2> struct SplitAt_helper;
template <typename _ValueT, unsigned _N, _ValueT... _FstXs, _ValueT _X,
          _ValueT... _SndXs>
struct SplitAt_helper<_N, ValueList<_ValueT, _FstXs...>,
                      ValueList<_ValueT, _X, _SndXs...>>
    : SplitAt_helper<_N - 1, ValueList<_ValueT, _FstXs..., _X>,
                     ValueList<_ValueT, _SndXs...>> {};
template <typename _ValueT, _ValueT... _FstXs, _ValueT _X, _ValueT... _SndXs>
struct SplitAt_helper<0, ValueList<_ValueT, _FstXs...>,
                      ValueList<_ValueT, _X, _SndXs...>>
    : TypePair<ValueList<_ValueT, _FstXs...>,
               ValueList<_ValueT, _X, _SndXs...>> {};
template <typename _ValueT, unsigned _N, _ValueT... _FstXs>
struct SplitAt_helper<_N, ValueList<_ValueT, _FstXs...>, ValueList<_ValueT>>
    : TypePair<ValueList<_ValueT, _FstXs...>, ValueList<_ValueT>> {};
template <typename _ValueT, _ValueT... _FstXs>
struct SplitAt_helper<0, ValueList<_ValueT, _FstXs...>, ValueList<_ValueT>>
    : TypePair<ValueList<_ValueT, _FstXs...>, ValueList<_ValueT>> {};
template <unsigned _N, typename _LstT>
using SplitAt =
    SplitAt_helper<_N, ValueList<typename _LstT::value_type>, _LstT>;

template <typename _LstT1, typename _LstT2> struct Append;
template <typename _ValueT, _ValueT... _L1s, _ValueT... _L2s>
struct Append<ValueList<_ValueT, _L1s...>, ValueList<_ValueT, _L2s...>> {
  using type = ValueList<_ValueT, _L1s..., _L2s...>;
};
template <typename _LstT1, typename _LstT2>
using Append_t = typename Append<_LstT1, _LstT2>::type;

template <template <auto> class _P, typename _LstT> struct All;
template <typename _ValueT, template <_ValueT> class _P, _ValueT... _Xs>
struct All<_P, ValueList<_ValueT, _Xs...>>
    : std::bool_constant<(... && _P<_Xs>::value)> {};
template <template <auto> class _P, typename _LstT>
constexpr bool All_v = All<_P, _LstT>::value;

template <typename _Keep, typename _LstT1, typename _LstT2>
struct Zip_helper {};
template <typename _ValueT, typename... _Pairs>
struct Zip_helper<TypeList<_Pairs...>, ValueList<_ValueT>, ValueList<_ValueT>> {
  using type = TypeList<_Pairs...>;
};
template <typename _ValueT, typename... _Pairs, _ValueT _X1, _ValueT... _X1s,
          _ValueT _X2, _ValueT... _X2s>
struct Zip_helper<TypeList<_Pairs...>, ValueList<_ValueT, _X1, _X1s...>,
                  ValueList<_ValueT, _X2, _X2s...>>
    : Zip_helper<TypeList<ValuePair<_ValueT, _X1, _X2>, _Pairs...>,
                 ValueList<_ValueT, _X1s...>, ValueList<_ValueT, _X2s...>> {};
template <typename _LstT1, typename _LstT2>
using Zip = Zip_helper<TypeList<>, _LstT1, _LstT2>;
template <typename _LstT1, typename _LstT2>
using Zip_t = typename Zip<_LstT1, _LstT2>::type;

/*******************************************************************************
 * Labels
 ******************************************************************************/

template <typename _LstT> struct Increasing;
template <typename... _PairT>
struct Increasing<TypeList<_PairT...>>
    : std::bool_constant<(... && (Lattice<typename _PairT::value_type>::leq(
                                     _PairT::first, _PairT::second)))> {};
template <typename _LstT>
constexpr bool Increasing_v = Increasing<_LstT>::value;

/*******************************************************************************
 * The Covert Type
 ******************************************************************************/

template <typename _LabelT, typename _T> struct is_Covert : std::false_type {};
template <typename _LabelT, typename _T, _LabelT... _Ls>
struct is_Covert<_LabelT, Covert<_LabelT, _T, _Ls...>> : std::true_type {};
template <typename _LabelT, typename _T>
constexpr bool is_Covert_v = is_Covert<_LabelT, _T>::value;

template <typename _LabelT, typename _T>
struct points_to_Covert : std::false_type {};
template <typename _LabelT, typename _T>
struct points_to_Covert<_LabelT, _T *>
    : std::integral_constant<
          bool, is_Covert_v<_LabelT, std::remove_cv_t<_T>> ||
                    points_to_Covert<_LabelT, std::remove_cv_t<_T>>::value> {};
template <typename _LabelT, typename _T>
constexpr bool points_to_Covert_v = points_to_Covert<_LabelT, _T>::value;

// _T is primitive if it is:
// - an arithmetic type (e.g. int, char, const unsigned, etc.)
// - an enum type
// - a non-function pointer, or pointer to a non-Covert type (of the same label)
template <typename _LabelT, typename _T>
struct is_primitive
    : std::integral_constant<
          bool, std::is_arithmetic<_T>::value || std::is_enum<_T>::value ||
                    (std::is_pointer<_T>::value && !is_function_pointer_v<_T> &&
                     !points_to_Covert_v<_LabelT, _T>)> {};
template <typename _LabelT, typename _T>
constexpr bool is_primitive_v = is_primitive<_LabelT, _T>::value;

/*******************************************************************************
 * Canonicalize
 ******************************************************************************/

// Construct an Covert type from a type and some labels
// Returns void if the type and labels are incompatible
template <typename _LabelT, typename _T, _LabelT... _Ls>
struct ConstructCovert_helper {
  using type = std::conditional_t<type_depth_v<_T> == sizeof...(_Ls),
                                  Covert<_LabelT, _T, _Ls...>, void>;
};
template <typename _LabelT, typename _T>
struct ConstructCovert_helper<_LabelT, _T> {
  using type = _T;
};
template <typename _LabelT, typename _T, _LabelT _L, _LabelT... _Ls>
struct ConstructCovert_helper<_LabelT, _T &&, _L, _Ls...> {
  using type =
      typename ConstructCovert_helper<_LabelT, _T, _L, _Ls...>::type &&;
};
template <typename _LabelT, typename _T, _LabelT _L, _LabelT... _Ls>
struct ConstructCovert_helper<_LabelT, _T &, _L, _Ls...> {
  using type = typename ConstructCovert_helper<_LabelT, _T, _L, _Ls...>::type &;
};
template <typename _LabelT, typename _T, _LabelT _L, _LabelT... _Ls>
struct ConstructCovert_helper<_LabelT, const _T, _L, _Ls...> {
  using type =
      const typename ConstructCovert_helper<_LabelT, _T, _L, _Ls...>::type;
};
template <typename _LabelT, typename _T, _LabelT _L, _LabelT... _Ls>
struct ConstructCovert_helper<_LabelT, volatile _T, _L, _Ls...> {
  using type =
      volatile typename ConstructCovert_helper<_LabelT, _T, _L, _Ls...>::type;
};
template <typename _LabelT, typename _T, _LabelT _L, _LabelT... _Ls>
struct ConstructCovert_helper<_LabelT, const volatile _T, _L, _Ls...> {
  using type = const volatile
      typename ConstructCovert_helper<_LabelT, _T, _L, _Ls...>::type;
};

template <typename _T, typename _ListT> struct ConstructCovert;
template <typename _LabelT, typename _T, _LabelT... _Ls>
struct ConstructCovert<_T, ValueList<_LabelT, _Ls...>>
    : ConstructCovert_helper<_LabelT, _T, _Ls...> {};
template <typename _T, typename _ListT>
using ConstructCovert_t = typename ConstructCovert<_T, _ListT>::type;

// Unwrap Covert types, e.g. in a function pointer or reference
// If a label type is given, then this will not unwrap Covert types
// with a different label. If _LabelT is 'void' then Unwrap will
// unwrap all Covert types
template <typename _T, typename _LabelT> struct Unwrap;

template <typename _T, typename _LabelT> struct Unwrap_cv {
  using type = typename Unwrap<_T, _LabelT>::type;
};
template <typename _T, typename _LabelT> struct Unwrap_cv<const _T, _LabelT> {
  using type = const typename Unwrap<_T, _LabelT>::type;
};
template <typename _T, typename _LabelT>
struct Unwrap_cv<volatile _T, _LabelT> {
  using type = volatile typename Unwrap<_T, _LabelT>::type;
};
template <typename _T, typename _LabelT>
struct Unwrap_cv<const volatile _T, _LabelT> {
  using type = const volatile typename Unwrap<_T, _LabelT>::type;
};

template <typename _T, typename _LabelT> struct Unwrap { using type = _T; };
template <typename _LabelT, typename _LabelArgT, typename _T, _LabelT... _Ls>
struct Unwrap<Covert<_LabelT, _T, _Ls...>, _LabelArgT> {
  using type = std::conditional_t<
      std::is_same_v<_LabelT, _LabelArgT> || std::is_void_v<_LabelArgT>,
      typename Unwrap_cv<_T, _LabelArgT>::type, Covert<_LabelT, _T, _Ls...>>;
};
template <typename _T, typename _LabelT> struct Unwrap<_T &, _LabelT> {
  using type = typename Unwrap_cv<_T, _LabelT>::type &;
};
template <typename _T, typename _LabelT> struct Unwrap<_T &&, _LabelT> {
  using type = typename Unwrap_cv<_T, _LabelT>::type &&;
};
template <typename _T, typename _LabelT> struct Unwrap<_T *, _LabelT> {
  using type = typename Unwrap_cv<_T, _LabelT>::type *;
};
template <std::size_t _N, typename _T, typename _LabelT>
struct Unwrap<_T[_N], _LabelT> {
  using type = typename Unwrap_cv<_T, _LabelT>::type[_N];
};
template <typename _T, typename _LabelT = void>
using Unwrap_t = typename Unwrap_cv<_T, _LabelT>::type;

template <bool _AddLabels, typename _T, typename _LstT>
struct GetLabels_aux_helper;
template <bool _AddLabels, typename _T, typename _LstT,
          typename _LabelT = typename _LstT::value_type>
struct GetLabels_aux {
  using type = std::conditional_t<
      is_primitive_v<_LabelT, _T> && _AddLabels,
      Append_t<ValueList<_LabelT, Lattice<_LabelT>::bottom>, _LstT>, _LstT>;
};
template <bool _AddLabels, typename _LstT>
struct GetLabels_aux<_AddLabels, void, _LstT> {
  using type = _LstT;
};
template <bool _AddLabels, typename _LabelT, typename _T, _LabelT... _Ls,
          _LabelT... _NewLs>
struct GetLabels_aux<_AddLabels, Covert<_LabelT, _T, _NewLs...>,
                     ValueList<_LabelT, _Ls...>>
    : GetLabels_aux_helper<false, _T, ValueList<_LabelT, _Ls..., _NewLs...>> {};
template <bool _AddLabels, typename _LabelT, typename _T, _LabelT... _Ls>
struct GetLabels_aux<_AddLabels, _T *, ValueList<_LabelT, _Ls...>>
    : GetLabels_aux_helper<
          _AddLabels, _T,
          std::conditional_t<
              _AddLabels, ValueList<_LabelT, _Ls..., Lattice<_LabelT>::bottom>,
              ValueList<_LabelT, _Ls...>>> {};
template <bool _AddLabels, typename _T, typename _Lst>
struct GetLabels_aux_helper
    : GetLabels_aux<_AddLabels, std::remove_cv_t<std::remove_reference_t<_T>>,
                    _Lst> {};
template <typename _LabelT, typename _T>
struct GetLabels : GetLabels_aux_helper<true, _T, ValueList<_LabelT>> {};
template <typename _LabelT, typename _T>
using GetLabels_t = typename GetLabels<_LabelT, _T>::type;

template <typename _LabelT, typename _T> struct canonicalize {
  using type =
      ConstructCovert_t<Unwrap_t<_T, _LabelT>, GetLabels_t<_LabelT, _T>>;
};
template <typename _LabelT, typename _T>
using canonicalize_t = typename canonicalize<_LabelT, _T>::type;

template <typename _LabelT, typename _T>
using is_canonical = std::is_same<_T, canonicalize_t<_LabelT, _T>>;
template <typename _LabelT, typename _T>
constexpr bool is_canonical_v = is_canonical<_LabelT, _T>::value;

template <typename _LabelT, typename _ArgT,
          typename = std::enable_if_t<is_canonical_v<_LabelT, _ArgT>>>
constexpr _ArgT make_canonical(_ArgT &&x) noexcept {
  return x;
}
template <typename _LabelT, typename _ArgT,
          typename = std::enable_if_t<!is_canonical_v<_LabelT, _ArgT>>,
          typename _RetT = canonicalize_t<_LabelT, _ArgT>>
constexpr _RetT make_canonical(_ArgT &&x) noexcept {
  using Cast =
      std::conditional_t<std::is_lvalue_reference<_RetT>::value,
                         _reinterpret_cast<_RetT>, _static_cast<_RetT>>;
  return Cast{}(x);
}

template <typename _LabelT, typename _T>
struct is_well_formed
    : std::integral_constant<bool, is_primitive_v<_LabelT, _T> ||
                                       is_canonical_v<_LabelT, _T>> {};
template <typename _LabelT, typename _T>
constexpr bool is_well_formed_v = is_well_formed<_LabelT, _T>::value;

template <typename _LabelT, typename _ArgT,
          typename = std::enable_if_t<is_well_formed_v<_LabelT, _ArgT>>>
constexpr _ArgT make_well_formed(_ArgT &&x) noexcept {
  return x;
}
template <typename _LabelT, typename _ArgT,
          typename = std::enable_if_t<!is_well_formed_v<_LabelT, _ArgT>>,
          typename _RetT = canonicalize_t<_LabelT, _ArgT>>
constexpr _RetT make_well_formed(_ArgT &&x) noexcept {
  using Cast =
      std::conditional_t<std::is_lvalue_reference<_RetT>::value,
                         _reinterpret_cast<_RetT>, _static_cast<_RetT>>;
  return Cast{}(x);
}

/*******************************************************************************
 * Casting Helpers
 ******************************************************************************/

template <typename _RT, typename... _ArgTs> using fptr = _RT (*)(_ArgTs...);

template <auto _L>
struct IsBottom : std::bool_constant<_L == Lattice<decltype(_L)>::bottom> {};

// Requires that the arguments be in canonical form
template <typename _CanonicalFromT, typename _CanonicalToT, bool Enable = false>
class is_covert_convertible_helper : public std::bool_constant<false> {};
template <typename _CanonicalFromT, typename _CanonicalToT>
class is_covert_convertible_helper<_CanonicalFromT, _CanonicalToT, true> {
  using __traits_FromT = covert_traits<_CanonicalFromT>;
  using __traits_ToT = covert_traits<_CanonicalToT>;
  using __labels_FromT = typename __traits_FromT::labels;
  using __labels_ToT = typename __traits_ToT::labels;
  static constexpr unsigned __num_labels_FromT = __traits_FromT::num_labels;
  static constexpr unsigned __num_labels_ToT = __traits_ToT::num_labels;

  static constexpr unsigned __num_labels_min =
      __num_labels_FromT < __num_labels_ToT ? __num_labels_FromT
                                            : __num_labels_ToT;
  using __new_labels_FromT = SplitAt<__num_labels_min, __labels_FromT>;
  using __new_labels_ToT = SplitAt<__num_labels_min, __labels_ToT>;

public:
  using value_type = bool;
  static constexpr value_type value =
      All_v<IsBottom, typename __new_labels_FromT::second_type> &&
      Increasing_v<Zip_t<typename __new_labels_FromT::first_type,
                         typename __new_labels_ToT::first_type>>;
  constexpr operator value_type() const noexcept { return value; }
};
template <typename _CanonicalFromT, typename _CanonicalToT>
struct is_covert_convertible
    : is_covert_convertible_helper<
          _CanonicalFromT, _CanonicalToT,
          std::is_same_v<typename covert_traits<_CanonicalFromT>::label_type,
                         typename covert_traits<_CanonicalToT>::label_type>> {};

template <typename _CanonicalFromT, typename _CanonicalToT>
constexpr bool is_covert_convertible_v =
    is_covert_convertible<_CanonicalFromT, _CanonicalToT>::value;

} // end namespace __covert_impl__
} // end namespace covert

#endif
