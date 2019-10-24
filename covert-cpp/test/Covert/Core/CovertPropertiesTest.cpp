// RUN: %clang-syntax -Xclang -verify %s
#include "Covert/SE.h"

// expected-no-diagnostics


static_assert(std::is_trivial<SE<int, L>>::value, "Value type not trivial");
static_assert(std::is_standard_layout<SE<int, L>>::value, "Value type not standard layout");
static_assert(std::is_pod<SE<int, L>>::value, "Value type not POD");
