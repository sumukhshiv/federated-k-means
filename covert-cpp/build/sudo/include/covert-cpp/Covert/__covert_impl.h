//===---- __covert_impl.h - Defines the Covert template implementation ----===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

////////////////////////////////////////////////////////////////////////////////
// __covert_impl.h
//
// Defines the implementation for the 'Covert' type and its operators.
////////////////////////////////////////////////////////////////////////////////

#ifndef __COVERT_IMPL_H__
#define __COVERT_IMPL_H__

#ifndef _MSC_VER
#define __COVERT_EMPTY_BASES__
#else
#define __COVERT_EMPTY_BASES__ __declspec(empty_bases)
#endif

namespace covert {

/*******************************************************************************
 * Covert Traits
 ******************************************************************************/

namespace __covert_impl__ {

template <typename _LabelT, _LabelT...> struct covert_label_traits {};
template <typename _LabelT, _LabelT _L, _LabelT... _Ls>
struct covert_label_traits<_LabelT, _L, _Ls...> {
  using labels = __covert_impl__::ValueList<_LabelT, _L, _Ls...>;
  static constexpr _LabelT label = _L;
  static constexpr unsigned num_labels = 1 + sizeof...(_Ls);
};

template <typename _T> struct covert_type_traits { using label_type = void; };
template <typename _LabelT, typename _T, _LabelT... _Ls>
struct covert_type_traits<Covert<_LabelT, _T, _Ls...>>
    : covert_label_traits<_LabelT, _Ls...> {
  using label_type = _LabelT;
  using value_type = _T;
  using reference = value_type &;
  using const_reference = const value_type &;
};
template <typename _T>
struct covert_type_traits<const _T> : covert_type_traits<_T> {
  using value_type = const typename covert_type_traits<_T>::value_type;
  using reference = const typename covert_type_traits<_T>::reference;
  using const_reference =
      const typename covert_type_traits<_T>::const_reference;
};
template <typename _T>
struct covert_type_traits<volatile _T> : covert_type_traits<_T> {
  using value_type = volatile typename covert_type_traits<_T>::value_type;
  using reference = volatile typename covert_type_traits<_T>::reference;
  using const_reference =
      volatile typename covert_type_traits<_T>::const_reference;
};
template <typename _T>
struct covert_type_traits<const volatile _T> : covert_type_traits<_T> {
  using value_type = const volatile typename covert_type_traits<_T>::value_type;
  using reference = const volatile typename covert_type_traits<_T>::reference;
  using const_reference =
      const volatile typename covert_type_traits<_T>::const_reference;
};
template <typename _T>
struct covert_type_traits<_T &> : covert_type_traits<_T> {
  using value_type = typename covert_type_traits<_T>::value_type &;
  using reference = typename covert_type_traits<_T>::reference &;
  using const_reference = typename covert_type_traits<_T>::const_reference &;
};
template <typename _T>
struct covert_type_traits<_T &&> : covert_type_traits<_T> {
  using value_type = typename covert_type_traits<_T>::value_type &&;
  using reference = typename covert_type_traits<_T>::reference &&;
  using const_reference = typename covert_type_traits<_T>::const_reference &&;
};

} // end namespace __covert_impl__

template <typename _T>
struct covert_traits : __covert_impl__::covert_type_traits<_T> {};

/*******************************************************************************
 * Covert Type Depth
 ******************************************************************************/

template <typename _T>
struct type_depth : std::integral_constant<unsigned, std::is_arithmetic_v<_T> ||
                                                         std::is_enum_v<_T>> {};
template <typename _T>
struct type_depth<_T *>
    : std::integral_constant<
          unsigned,
          std::is_function_v<_T> ? 0 : type_depth_v<std::remove_cv_t<_T>> + 1> {
};

/*******************************************************************************
 * Covert Arithmetic Operators
 ******************************************************************************/

namespace __covert_impl__ {

template <typename _ThisT> class Covert_Arith_Ops {
#define COVERT_ARITH_UNARY(op)                                                 \
  template <typename _T = __value_type,                                        \
            typename = decltype(op std::declval<_T>())>                        \
  inline _ThisT operator op() {                                                \
    __COVERT_LOG__(_ThisT, "operator" #op);                                    \
    const _ThisT &ct = static_cast<const _ThisT &>(*this);                     \
    return op __covert_extract__(ct);                                          \
  }
#define COVERT_LOGIC_UNARY(op)                                                 \
  template <typename _T = __value_type,                                        \
            typename _RetValueT = decltype(op std::declval<_T>()),             \
            typename _RetT = ConstructCovert_t<                                \
                _RetValueT, ValueList<__label_type, __label>>,                 \
            typename = std::enable_if_t<!std::is_void_v<_RetT>>>               \
  __COVERT_CONSTEXPR__ _RetT operator op() const {                             \
    __COVERT_LOG__(_ThisT, "operator" #op);                                    \
    const _ThisT &ct = static_cast<const _ThisT &>(*this);                     \
    return op __covert_extract__(ct);                                          \
  }
#define COVERT_ARITH_INCREMENT(op)                                             \
  template <typename _T = __value_type,                                        \
            typename = decltype(op std::declval<_T &>())>                      \
  inline _ThisT &operator op() {                                               \
    __COVERT_LOG__(_ThisT, "operator" #op " (prefix)");                        \
    _ThisT &t = static_cast<_ThisT &>(*this);                                  \
    op __covert_extract__(t);                                                  \
    return t;                                                                  \
  }                                                                            \
  template <typename _T = __value_type,                                        \
            typename = decltype(std::declval<_T &>() op)>                      \
  inline _ThisT operator op(int) {                                             \
    __COVERT_LOG__(_ThisT, "operator" #op " (postfix)");                       \
    _ThisT &t = static_cast<_ThisT &>(*this);                                  \
    _ThisT tmp = t;                                                            \
    __covert_extract__(t) op;                                                  \
    return tmp;                                                                \
  }

  using __traits = covert_traits<_ThisT>;
  using __label_type = typename __traits::label_type;
  using __value_type = typename __traits::value_type;
  using __labels = typename __traits::labels;
  static constexpr __label_type __label = __traits::label;

public:
  COVERT_ARITH_UNARY(+);
  COVERT_ARITH_UNARY(-);
  COVERT_ARITH_UNARY(~);
  COVERT_LOGIC_UNARY(!);
  COVERT_ARITH_INCREMENT(++);
  COVERT_ARITH_INCREMENT(--);

#undef COVERT_ARITH_UNARY
#undef COVERT_LOGIC_UNARY
#undef COVERT_ARITH_INCREMENT
};

template <typename _LabelT1, typename _LabelT2> struct BinaryArithLabel {};
template <> struct BinaryArithLabel<void, void> {};
template <typename _LabelT> struct BinaryArithLabel<_LabelT, _LabelT> {
  using type = _LabelT;
};
template <typename _LabelT> struct BinaryArithLabel<void, _LabelT> {
  using type = _LabelT;
};
template <typename _LabelT> struct BinaryArithLabel<_LabelT, void> {
  using type = _LabelT;
};

#define COVERT_ARITH_BINARY_ASSIGN(op)                                         \
  template <                                                                   \
      typename _ArgT1, typename _ArgT2,                                        \
      typename _LabelT1 = typename covert_traits<_ArgT1>::label_type,          \
      typename _LabelT2 = typename covert_traits<_ArgT2>::label_type,          \
      typename _LabelT = typename BinaryArithLabel<_LabelT1, _LabelT2>::type,  \
      typename _CanonicalArgT1 = canonicalize_t<_LabelT, _ArgT1>,              \
      typename _CanonicalArgT2 = canonicalize_t<_LabelT, _ArgT2>,              \
      typename _ArgT1_traits = covert_traits<_CanonicalArgT1>,                 \
      typename _ArgT2_traits = covert_traits<_CanonicalArgT2>,                 \
      typename _ArgT1_ValueT = typename _ArgT1_traits::value_type,             \
      typename _ArgT2_ValueT = typename _ArgT2_traits::value_type,             \
      typename _RetValueT = decltype(std::declval<_ArgT1_ValueT &>()           \
                                         op std::declval<_ArgT2_ValueT>()),    \
      _LabelT _ArgT1_L = _ArgT1_traits::label,                                 \
      _LabelT _ArgT2_L = _ArgT2_traits::label,                                 \
      typename = std::enable_if_t<Lattice<_LabelT>::leq(_ArgT2_L, _ArgT1_L)>>  \
  inline _ArgT1 &operator op(_ArgT1 &_x, const _ArgT2 &_y) {                   \
    __COVERT_LOG2__(_ArgT1, _ArgT2, "operator" #op);                           \
    auto &x = reinterpret_cast<canonicalize_t<_LabelT, _ArgT1 &>>(_x);         \
    auto y = static_cast<canonicalize_t<_LabelT, _ArgT2>>(_y);                 \
    __covert_extract__(x) op __covert_extract__(y);                            \
    return _x;                                                                 \
  }

#define COVERT_LOGIC_ARITH_BINARY(op)                                          \
  template <                                                                   \
      typename _ArgT1, typename _ArgT2,                                        \
      typename _LabelT1 = typename covert_traits<_ArgT1>::label_type,          \
      typename _LabelT2 = typename covert_traits<_ArgT2>::label_type,          \
      typename _LabelT = typename BinaryArithLabel<_LabelT1, _LabelT2>::type,  \
      typename _CanonicalArgT1 = canonicalize_t<_LabelT, _ArgT1>,              \
      typename _CanonicalArgT2 = canonicalize_t<_LabelT, _ArgT2>,              \
      typename _ArgT1_traits = covert_traits<_CanonicalArgT1>,                 \
      typename _ArgT2_traits = covert_traits<_CanonicalArgT2>,                 \
      typename _ArgT1_ValueT = typename _ArgT1_traits::value_type,             \
      typename _ArgT2_ValueT = typename _ArgT2_traits::value_type,             \
      typename _RetValueT = decltype(std::declval<_ArgT1_ValueT>()             \
                                         op std::declval<_ArgT2_ValueT>()),    \
      _LabelT _ArgT1_L = _ArgT1_traits::label,                                 \
      _LabelT _ArgT2_L = _ArgT2_traits::label,                                 \
      typename _ArgT1_Ls = typename _ArgT1_traits::labels,                     \
      typename _ArgT2_Ls = typename _ArgT2_traits::labels,                     \
      typename _RetLs = Append_t<                                              \
          ValueList<_LabelT, Lattice<_LabelT>::join(_ArgT1_L, _ArgT2_L)>,      \
          std::conditional_t<                                                  \
              std::is_pointer<_RetValueT>::value,                              \
              std::conditional_t<std::is_pointer<_ArgT1_ValueT>::value,        \
                                 Tail_t<_ArgT1_Ls>, Tail_t<_ArgT2_Ls>>,        \
              ValueList<_LabelT>>>,                                            \
      typename _RetT = ConstructCovert_t<_RetValueT, _RetLs>,                  \
      typename = std::enable_if_t<!std::is_void_v<_RetT>>>                     \
  __COVERT_CONSTEXPR__ _RetT operator op(const _ArgT1 &_x, const _ArgT2 &_y) { \
    __COVERT_LOG2__(_ArgT1, _ArgT2, "operator" #op);                           \
    auto x = static_cast<canonicalize_t<_LabelT, _ArgT1>>(_x);                 \
    auto y = static_cast<canonicalize_t<_LabelT, _ArgT2>>(_y);                 \
    return __covert_extract__(x) op __covert_extract__(y);                     \
  }

COVERT_ARITH_BINARY_ASSIGN(+=);
COVERT_ARITH_BINARY_ASSIGN(-=);
COVERT_ARITH_BINARY_ASSIGN(*=);
COVERT_ARITH_BINARY_ASSIGN(/=);
COVERT_ARITH_BINARY_ASSIGN(%=);
COVERT_ARITH_BINARY_ASSIGN(^=);
COVERT_ARITH_BINARY_ASSIGN(&=);
COVERT_ARITH_BINARY_ASSIGN(|=);
COVERT_ARITH_BINARY_ASSIGN(>>=);
COVERT_ARITH_BINARY_ASSIGN(<<=);
COVERT_LOGIC_ARITH_BINARY(<);
COVERT_LOGIC_ARITH_BINARY(>);
COVERT_LOGIC_ARITH_BINARY(==);
COVERT_LOGIC_ARITH_BINARY(!=);
COVERT_LOGIC_ARITH_BINARY(<=);
COVERT_LOGIC_ARITH_BINARY(>=);
COVERT_LOGIC_ARITH_BINARY(+);
COVERT_LOGIC_ARITH_BINARY(-);
COVERT_LOGIC_ARITH_BINARY(*);
COVERT_LOGIC_ARITH_BINARY(/);
COVERT_LOGIC_ARITH_BINARY(%);
COVERT_LOGIC_ARITH_BINARY (^);
COVERT_LOGIC_ARITH_BINARY(&);
COVERT_LOGIC_ARITH_BINARY(|);
COVERT_LOGIC_ARITH_BINARY(<<);
COVERT_LOGIC_ARITH_BINARY(>>);

#undef COVERT_ARITH_BINARY_ASSIGN
#undef COVERT_LOGIC_ARITH_BINARY

} // end namespace __covert_impl__

/*******************************************************************************
 * Covert Pointer Operations
 ******************************************************************************/

namespace __covert_impl__ {

/// \brief This class defines operations on pointers, assuming the
/// given type T is a pointer
template <typename _ThisT> class Covert_Pointer_Ops {
  using __label_type = typename covert_traits<_ThisT>::label_type;
  using __CanonicalThisT = canonicalize_t<__label_type, _ThisT>;
  using __traits = covert_traits<__CanonicalThisT>;
  using __value_type = typename __traits::value_type;
  using __labels = typename __traits::labels;
  static constexpr __label_type __label = __traits::label;

public:
  template <
      typename _U = __value_type, __label_type _L = __label,
      typename _RetValue =
          decltype(std::declval<_U &>()[std::declval<std::size_t>()]),
      typename _RetLs = std::enable_if_t<IsBottom<_L>::value, Tail_t<__labels>>,
      typename _RetT = ConstructCovert_t<_RetValue, _RetLs>,
      typename = std::enable_if_t<!std::is_void_v<_RetT>>>
  inline _RetT operator[](std::size_t i) {
    __COVERT_LOG__(_ThisT, "Pointer index operator");
    _ThisT &t = static_cast<_ThisT &>(*this);
    return reinterpret_cast<_RetT>(__covert_extract__(t)[i]);
  }
  template <
      typename _U = __value_type, __label_type _L = __label,
      typename _RetValue = decltype(*std::declval<_U &>()),
      typename _RetLs = std::enable_if_t<IsBottom<_L>::value, Tail_t<__labels>>,
      typename _RetT = ConstructCovert_t<_RetValue, _RetLs>,
      typename = std::enable_if_t<!std::is_void_v<_RetT>>>
  inline _RetT operator*() {
    __COVERT_LOG__(_ThisT, "Pointer dereference operator");
    _ThisT &t = static_cast<_ThisT &>(*this);
    return reinterpret_cast<_RetT>(*__covert_extract__(t));
  }
  template <__label_type _L = __label,
            typename = std::enable_if_t<IsBottom<_L>::value>>
  inline __value_type operator->() const {
    __COVERT_LOG__(_ThisT, "Pointer member access operator");
    const _ThisT &ct = static_cast<const _ThisT &>(*this);
    return __covert_extract__(ct);
  }
  template <__label_type _L = __label, typename _Labels = __labels,
            typename _ValueT = __value_type,
            typename = std::enable_if_t<std::is_pointer_v<_ValueT>>,
            typename = std::enable_if_t<!All_v<IsBottom, _Labels>>,
            typename = std::enable_if_t<IsBottom<_L>::value>>
  __COVERT_CONSTEXPR__ operator bool() const {
    __COVERT_LOG_CAST__("Pointer to bool conversion", _ThisT, bool);
    const _ThisT &ct = static_cast<const _ThisT &>(*this);
    return static_cast<bool>(__covert_extract__(ct));
  }
};

} // end namespace __covert_impl__

/*******************************************************************************
 * Covert Conversions
 ******************************************************************************/

namespace __covert_impl__ {

template <typename _ThisT, typename Enable = void>
class Covert_PrimitiveConversions {};
template <typename _ThisT>
class Covert_PrimitiveConversions<
    _ThisT, std::enable_if_t<
                All_v<IsBottom, typename covert_traits<canonicalize_t<
                                    typename covert_traits<_ThisT>::label_type,
                                    _ThisT>>::labels>>> {
  using __label_type = typename covert_traits<_ThisT>::label_type;
  using __CanonicalThisT = canonicalize_t<__label_type, _ThisT>;
  using __traits = covert_traits<__CanonicalThisT>;
  using __reference = typename __traits::reference;
  using __const_reference = typename __traits::const_reference;

public:
  inline operator __reference() {
    __COVERT_LOG_CAST__("Implicit primitive type conversion (reference)",
                        _ThisT, __reference);
    _ThisT &t = static_cast<_ThisT &>(*this);
    return __covert_extract__(t);
  }
  __COVERT_CONSTEXPR__ operator __const_reference() const {
    __COVERT_LOG_CAST__("Implicit primitive type conversion (const reference)",
                        _ThisT, __const_reference);
    const _ThisT &ct = static_cast<const _ThisT &>(*this);
    return __covert_extract__(ct);
  }
};

template <typename _ThisT> class Covert_CanonicalConversions {
  using __label_type = typename covert_traits<_ThisT>::label_type;

public:
  template <typename _T, typename _RetT = _T *,
            typename = std::enable_if_t<!is_well_formed_v<__label_type, _RetT>>,
            typename _CanonicalRetT = canonicalize_t<__label_type, _RetT>,
            typename =
                std::enable_if_t<std::is_convertible_v<_ThisT, _CanonicalRetT>>>
  inline operator _T *() const {
    __COVERT_LOG_CAST__("Implicit Covert canonical conversion (pointer)",
                        _ThisT, _RetT);
    const _ThisT &ct = static_cast<const _ThisT &>(*this);
    return reinterpret_cast<_RetT>(__covert_extract__(ct));
  }
};

template <typename _ThisT> struct DecayOperator_helper {
  using __label_type = typename covert_traits<_ThisT>::label_type;
  using __CanonicalThisT = canonicalize_t<__label_type, _ThisT>;
  using __traits = covert_traits<__CanonicalThisT>;
  using __value_type = typename __traits::value_type;
  using __labels = typename __traits::labels;

  using decay_type = std::add_pointer_t<
      ConstructCovert_t<std::remove_pointer_t<__value_type>, Tail_t<__labels>>>;
  static constexpr bool needs_decay_op =
      IsBottom<Head_v<__labels>>::value && !All_v<IsBottom, Tail_t<__labels>>;
};

template <typename _ThisT, typename _Enable = void>
class Covert_DecayConversions {};
template <typename _ThisT>
class Covert_DecayConversions<
    _ThisT, std::enable_if_t<DecayOperator_helper<_ThisT>::needs_decay_op>> {
  using __decay_type = typename DecayOperator_helper<_ThisT>::decay_type;

public:
  inline operator __decay_type() const {
    __COVERT_LOG_CAST__("Implicit pointer decay", _ThisT, __decay_type);
    const _ThisT &ct = static_cast<const _ThisT &>(*this);
    return reinterpret_cast<__decay_type>(__covert_extract__(ct));
  }
};

template <typename _ThisT>
struct __COVERT_EMPTY_BASES__ Covert_Conversions
    : Covert_PrimitiveConversions<_ThisT>,
                            Covert_CanonicalConversions<_ThisT>,
                            Covert_DecayConversions<_ThisT> {};

} // end namespace __covert_impl__

/*******************************************************************************
 * Covert Address-Of
 ******************************************************************************/

namespace __covert_impl__ {

template <typename _ThisT> class Covert_AddressOf_Ops {
  using __label_type = typename covert_traits<_ThisT>::label_type;

public:
  template <typename _RetT = canonicalize_t<
                __label_type, decltype(&std::declval<_ThisT &>())>>
  inline _RetT operator&() {
    __COVERT_LOG__(_ThisT, "Address of");
    _ThisT &t = static_cast<_ThisT &>(*this);
    return &__covert_extract__(t);
  }
  template <typename _RetT = canonicalize_t<
                __label_type, decltype(&std::declval<const _ThisT &>())>>
  __COVERT_CONSTEXPR__ _RetT operator&() const {
    __COVERT_LOG__(_ThisT, "Address of (const)");
    const _ThisT &ct = static_cast<const _ThisT &>(*this);
    return &__covert_extract__(ct);
  }
};

} // end namespace __covert_impl__

/*******************************************************************************
 * Covert Base Type
 ******************************************************************************/

namespace __covert_impl__ {

template <typename _ThisT> class Covert_Base {
  using __traits = covert_traits<_ThisT>;
  using __label_type = typename __traits::label_type;
  using __value_type = typename __traits::value_type;
  using __reference = typename __traits::reference;
  using __const_reference = typename __traits::const_reference;
  using __labels = typename __traits::labels;
  using _CanonicalThisT = canonicalize_t<__label_type, _ThisT>;

  __value_type __M_val__;

public:
  template <typename _T> friend class Covert_Base;
  friend constexpr __reference
  __covert_extract__(Covert_Base<_ThisT> &x) noexcept {
    return x.__M_val__;
  }
  friend constexpr __const_reference
  __covert_extract__(const Covert_Base<_ThisT> &x) noexcept {
    return x.__M_val__;
  }

  Covert_Base() = default;
  ~Covert_Base() = default;
  Covert_Base(const Covert_Base<_ThisT> &) = default;
  Covert_Base<_ThisT> &operator=(const Covert_Base<_ThisT> &) = default;

  __COVERT_CONSTEXPR__ Covert_Base(const __value_type &x) : __M_val__(x) {
    __COVERT_LOG_CONSTRUCTOR__("Converting constructor (primitive)", _ThisT,
                               __value_type);
  }
  template <
      typename _ArgT,
      typename _CanonicalArgT = canonicalize_t<__label_type, _ArgT>,
      typename =
          std::enable_if_t<is_covert_convertible_v<_CanonicalArgT, _ThisT>>,
      typename _ArgValueT = typename covert_traits<_CanonicalArgT>::value_type,
      typename =
          std::enable_if_t<std::is_constructible_v<__value_type, _ArgValueT>>>
  __COVERT_CONSTEXPR__ Covert_Base(const Covert_Base<_ArgT> &x)
      : __M_val__(std::conditional_t<is_canonical_v<__label_type, _ArgT>,
                                     _static_cast<__value_type>,
                                     _reinterpret_cast<__value_type>>{}(
            x.__M_val__)) {
    __COVERT_LOG_CONSTRUCTOR__("Converting constructor (Covert)", _ThisT,
                               _ArgT);
  }
  template <typename _U, typename _ArgT = _U *,
            typename = std::enable_if_t<!is_well_formed_v<__label_type, _ArgT>>,
            typename _CanonicalArgT = canonicalize_t<__label_type, _ArgT>,
            typename = std::enable_if_t<
                std::is_constructible_v<_ThisT, _CanonicalArgT>>>
  inline Covert_Base(_U *x) : __M_val__(reinterpret_cast<__value_type>(x)) {
    __COVERT_LOG_CONSTRUCTOR__("Converting constructor (canonicalize pointer)",
                               _ThisT, _ArgT);
  }
};

template <typename _ThisT, template <typename> class... _Policy>
struct __COVERT_EMPTY_BASES__ Covert_Mixin : _Policy<_ThisT>... {};

template <typename _ThisT>
struct Covert_impl
    : Covert_Base<_ThisT>,
      Covert_Mixin<_ThisT, Covert_Conversions, Covert_AddressOf_Ops,
                   Covert_Arith_Ops, Covert_Pointer_Ops> {
  using Covert_Base<_ThisT>::Covert_Base;
};

template <typename _ThisT, typename _Enable = void> struct Covert_check {};
template <typename _LabelT, typename _T, _LabelT... _Ls>
struct Covert_check<
    Covert<_LabelT, _T, _Ls...>,
    std::enable_if_t<!(std::is_const_v<_T> ||
                       std::is_volatile_v<_T>)&&!std::is_reference_v<_T> &&
                     !std::is_array_v<_T> &&
                     (type_depth_v<_T> == sizeof...(_Ls))>>
    : Covert_impl<Covert<_LabelT, _T, _Ls...>> {
  using Covert_impl<Covert<_LabelT, _T, _Ls...>>::Covert_impl;
};

} // end namespace __covert_impl__

template <typename _LabelT, typename _T, _LabelT _L, _LabelT... _Ls>
struct Covert : __covert_impl__::Covert_check<Covert<_LabelT, _T, _L, _Ls...>> {
  static_assert(!(std::is_const_v<_T> || std::is_volatile_v<_T>),
                "Cannot encapsulate a const and/or volatile type");
  static_assert(!std::is_reference_v<_T>,
                "Cannot encapsulate a reference type");
  static_assert(!std::is_array_v<_T>, "Cannot encapsulate an array type");
  static_assert(type_depth_v<_T> == 1 + sizeof...(_Ls),
                "Incorrect number of labels for this type");

  using __covert_impl__::Covert_check<
      Covert<_LabelT, _T, _L, _Ls...>>::Covert_check;
};

} // end namespace covert

#endif
