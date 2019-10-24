// RUN: %clang-syntax -Xclang -verify %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert;
using namespace covert::__covert_impl__;

using l = unsigned;
using cov = Covert<l, int, 2>;
using sec = SE<int, L>;

static_assert(is_Covert_v<l, cov>);
static_assert(!is_Covert_v<l, unsigned>);
static_assert(!is_Covert_v<l, cov *>);
static_assert(!is_Covert_v<l, const cov>);
static_assert(is_Covert_v<SLabel, sec>);

static_assert(!points_to_Covert_v<l, cov>);
static_assert(!points_to_Covert_v<l, int *>);
static_assert(!points_to_Covert_v<l, const void *>);
static_assert(points_to_Covert_v<l, cov *>);
static_assert(points_to_Covert_v<l, const cov *>);
static_assert(points_to_Covert_v<l, volatile cov *>);
static_assert(points_to_Covert_v<l, const volatile cov *>);
static_assert(points_to_Covert_v<l, const volatile cov *>);
static_assert(points_to_Covert_v<l, const volatile cov **>);
