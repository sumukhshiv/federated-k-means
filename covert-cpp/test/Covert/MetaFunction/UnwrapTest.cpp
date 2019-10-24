// RUN: %clang-llvm -Xclang -verify %s -o %t.bc
#include "../include/MPCLattice.h"
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_impl__;

static_assert(std::is_same<Unwrap_t<SE<int, L>>, int>::value);
static_assert(std::is_same<Unwrap_t<const SE<int, L>>, const int>::value);
static_assert(std::is_same<Unwrap_t<volatile SE<int, L>>, volatile int>::value);
static_assert(std::is_same<Unwrap_t<const volatile SE<int, L>>,
                           const volatile int>::value);
static_assert(std::is_same<Unwrap_t<const int>, const int>::value);
static_assert(std::is_same<Unwrap_t<SE<const int &, L>>, const int &>::value);
static_assert(std::is_same<Unwrap_t<const SE<int, L>> &, const int &>::value);
static_assert(std::is_same<Unwrap_t<const SE<int, L>> &&, const int &&>::value);
static_assert(std::is_same<Unwrap_t<SE<int *, L, L>>, int *>::value);
static_assert(std::is_same<Unwrap_t<const SE<int *, L, L>>, int *const>::value);
static_assert(std::is_same<Unwrap_t<const SE<const int *, L, L>>,
                           const int *const>::value);
static_assert(std::is_same<Unwrap_t<const SE<const int *const *, L, L>>,
                           const int *const *const>::value);
static_assert(std::is_same<Unwrap_t<SE<int, L> *>, int *>::value);
static_assert(std::is_same<Unwrap_t<SE<int, L> *const>, int *const>::value);
static_assert(
    std::is_same<Unwrap_t<const SE<int, L> *const>, const int *const>::value);
static_assert(std::is_same<Unwrap_t<const SE<int, L> *>, const int *>::value);
static_assert(std::is_same<Unwrap_t<SE<const int[4], L>>, const int[4]>::value);
static_assert(
    std::is_same<Unwrap_t<SE<const int (&)[4], L>>, const int (&)[4]>::value);
static_assert(std::is_same<Unwrap_t<SE<SE<int, H> *, H>>, int *>::value);
static_assert(std::is_same<Unwrap_t<SE<int *, L, H> *>, int **>::value);

// with label argument
static_assert(std::is_same<Unwrap_t<MPC<SE<int, L> *, Bob>, MPCLabel>,
                           SE<int, L> *>::value);
static_assert(std::is_same<Unwrap_t<MPC<SE<int, L> *, Bob>, SLabel>,
                           MPC<SE<int, L> *, Bob>>::value);
static_assert(std::is_same<Unwrap_t<MPC<SE<int, L> *, Bob>, void>,
                           int *>::value);
