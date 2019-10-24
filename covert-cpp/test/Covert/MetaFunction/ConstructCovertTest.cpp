// RUN: %clang-syntax -Xclang -verify %s
#include "Covert/SE.h"
#include "../include/MPCLattice.h"

// expected-no-diagnostics

using namespace covert::__covert_impl__;

template <SLabel... _Ls> using SLabelList = ValueList<SLabel, _Ls...>;
template <MPCLabel... _Ls> using MPCLabelList = ValueList<MPCLabel, _Ls...>;

struct C {};

// succeed
static_assert(std::is_same_v<ConstructCovert_t<C, SLabelList<>>, C>);
static_assert(
    std::is_same_v<ConstructCovert_t<SE<int, H>, SLabelList<>>, SE<int, H>>);
static_assert(
    std::is_same_v<ConstructCovert_t<int, SLabelList<H>>, SE<int, H>>);
static_assert(std::is_same_v<ConstructCovert_t<int *, SLabelList<H, L>>,
                             SE<int *, H, L>>);
static_assert(
    std::is_same_v<ConstructCovert_t<int *const volatile, SLabelList<H, L>>,
                   const volatile SE<int *, H, L>>);
static_assert(
    std::is_same_v<ConstructCovert_t<int *const &, SLabelList<H, L>>,
                   const SE<int *, H, L> &>);
static_assert(
    std::is_same_v<ConstructCovert_t<int *const &&, SLabelList<H, L>>,
                   const SE<int *, H, L> &&>);
static_assert(
    std::is_same_v<ConstructCovert_t<SE<int, L> *, MPCLabelList<Bob>>,
                   MPC<SE<int, L> *, Bob>>);

// fail
static_assert(std::is_same_v<ConstructCovert_t<C, SLabelList<L>>, void>);
static_assert(std::is_same_v<ConstructCovert_t<int *, SLabelList<L>>, void>);
