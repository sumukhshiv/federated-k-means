// RUN: %clang-llvm -Xclang -verify %s -o %t.bc
#include "Covert/Covert.h"

// expected-no-diagnostics

using namespace covert::__covert_impl__;

static_assert(is_function_pointer_v<int (*)(void)>);
static_assert(is_function_pointer_v<int &(*)(int &)>);
static_assert(is_function_pointer_v<int &(*const)(int &)>);
static_assert(!is_function_pointer_v<int *>);

static_assert(is_primitive_v<void, int>);
static_assert(is_primitive_v<void, int *>);
static_assert(!is_primitive_v<void, int *&>);
static_assert(!is_primitive_v<void, int &(*)(int &)>);
