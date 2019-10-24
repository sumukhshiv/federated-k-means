// RUN: %clang-llvm -Xclang -verify %s -o %t.bc
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_impl__;

static_assert(is_covert_convertible_v<SE<int *, L, L>, SE<const int *, H, H>>, "");
