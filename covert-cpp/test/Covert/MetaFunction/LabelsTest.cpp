// RUN: %clang-syntax -Xclang -verify %s
#include "Covert/SE.h"
#include "../include/MPCLattice.h"

// expected-no-diagnostics

using namespace covert;
using namespace covert::__covert_impl__;

static_assert(!Lattice<MPCLabel>::leq(Alice, Bob), "");
static_assert(!Lattice<MPCLabel>::leq(Bob, Alice), "");
static_assert(Lattice<MPCLabel>::leq(Bob, Everyone), "");
static_assert(!Lattice<MPCLabel>::leq(Everyone, Bob), "");
static_assert(Lattice<MPCLabel>::leq(Bob, Bob), "");
static_assert(Lattice<MPCLabel>::leq(Public, Bob), "");
static_assert(Lattice<MPCLabel>::join(Alice, Bob) == AliceBob, "");
static_assert(Lattice<MPCLabel>::join(Alice, Everyone) == Everyone, "");
static_assert(Lattice<MPCLabel>::join(Public, Everyone) == Everyone, "");
static_assert(Lattice<MPCLabel>::join(Bob, Everyone) == Everyone, "");

template <MPCLabel... _Ls> using LList = ValueList<MPCLabel, _Ls...>;
using lst1 = LList<Public, Alice, Everyone>;
using lst2 = LList<Public, Alice, Alice>;
using lst3 = LList<Public, Alice, Bob>;

static_assert(Increasing_v<Zip_t<lst2, lst1>>, "");
static_assert(!Increasing_v<Zip_t<lst1, lst2>>, "");
static_assert(!Increasing_v<Zip_t<lst2, lst3>>, "");
static_assert(!Increasing_v<Zip_t<lst3, lst2>>, "");
