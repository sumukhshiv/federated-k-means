// RUN: %clang-syntax -Xclang -verify %s
#include "../include/MPCLattice.h"
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_impl__;

template <SLabel... _Ls> using SLabelList = ValueList<SLabel, _Ls...>;
template <MPCLabel... _Ls> using MPCLabelList = ValueList<MPCLabel, _Ls...>;

static_assert(std::is_same_v<GetLabels_t<SLabel, void>, SLabelList<>>);
static_assert(std::is_same_v<GetLabels_t<SLabel, int>, SLabelList<L>>);
static_assert(
    std::is_same_v<GetLabels_t<SLabel, const int *>, SLabelList<L, L>>);
static_assert(std::is_same_v<GetLabels_t<SLabel, SE<SE<int, L> *, H> *>,
                             SLabelList<L, H, L>>);

static_assert(
    std::is_same_v<GetLabels_t<SLabel, MPC<int, Alice>>, SLabelList<>>);
static_assert(
    std::is_same_v<GetLabels_t<SLabel, MPC<int, Alice> *>, SLabelList<L>>);
static_assert(std::is_same_v<GetLabels_t<SLabel, SE<MPC<int, Alice> *, L>>,
                             SLabelList<L>>);
static_assert(std::is_same_v<GetLabels_t<SLabel, MPC<SE<int, L> *, Alice>>,
                             SLabelList<>>);
static_assert(std::is_same_v<GetLabels_t<MPCLabel, MPC<SE<int, L> *, Alice>>,
                             MPCLabelList<Alice>>);
