// RUN: %clang-syntax -Xclang -verify %s
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert;
using namespace covert::__covert_impl__;

static_assert(type_depth_v<int> == 1);
static_assert(type_depth_v<int *> == 2);
static_assert(type_depth_v<const int *> == 2);
static_assert(type_depth_v<const int *const*> == 3);
static_assert(type_depth_v<const void *> == 1);
static_assert(type_depth_v<void> == 0);

using cov = Covert<unsigned, int, 2>;
static_assert(type_depth_v<cov *> == 1);
static_assert(type_depth_v<const cov *> == 1);
