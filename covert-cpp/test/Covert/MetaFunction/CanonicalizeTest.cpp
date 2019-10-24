// RUN: %clang-llvm -Xclang -verify %s -o %t.bc
#include "../include/MPCLattice.h"
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_impl__;

static_assert(
    std::is_same<canonicalize_t<SLabel, SE<int, L>>, SE<int, L>>::value);
static_assert(
    std::is_same<canonicalize_t<SLabel, SE<int, L> *>, SE<int *, L, L>>::value);
static_assert(std::is_same<canonicalize_t<SLabel, const SE<int, L> *const>,
                           const SE<const int *, L, L>>::value);
static_assert(std::is_same<canonicalize_t<SLabel, SE<SE<int, H> *, H>>,
                           SE<int *, H, H>>::value);
static_assert(std::is_same<canonicalize_t<SLabel, SE<SE<SE<int, L> *, H> *, H>>,
                           SE<int **, H, H, L>>::value);

static_assert(std::is_same<canonicalize_t<MPCLabel, SE<int *, L, L>>,
                           SE<int *, L, L>>::value);
static_assert(std::is_same<canonicalize_t<MPCLabel, MPC<SE<int, L> *, Bob>>,
                           MPC<SE<int, L> *, Bob>>::value);
static_assert(std::is_same<canonicalize_t<MPCLabel, MPC<SE<int, L> *, Bob> *>,
                           MPC<SE<int, L> **, Public, Bob>>::value);
