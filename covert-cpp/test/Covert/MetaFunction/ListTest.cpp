// RUN: %clang-syntax -Xclang -verify %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_impl__;

template <unsigned... _Xs> using UList = ValueList<unsigned, _Xs...>;
using lst = UList<1, 2, 3>;

static_assert(Head_v<lst> == 1);
static_assert(std::is_same_v<Tail_t<lst>, UList<2, 3>>);
using split = SplitAt<2, lst>;
using split_first = typename split::first_type;
using split_second = typename split::second_type;
static_assert(std::is_same_v<split_first, UList<1, 2>>);
static_assert(std::is_same_v<split_second, UList<3>>);
static_assert(std::is_same_v<Append_t<split_first, split_second>, lst>);
template <unsigned _L> struct NIsZero : std::integral_constant<bool, _L != 0> {};
template <unsigned _L> struct NIsOne : std::integral_constant<bool, _L != 1> {};
static_assert(All_v<NIsZero, lst>);
static_assert(!All_v<NIsOne, lst>);
