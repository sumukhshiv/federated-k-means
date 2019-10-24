// RUN: %clang-llvmo -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %llio %t.bc | %FileCheck %s
#include "Covert/cov_algorithm.h"
#include "Covert/SE.h"
#include <forward_list>

// expected-no-diagnostics

using namespace covert::__covert_logging__;

using FwdList = std::forward_list<SE<int, H>>;
using FwdListIt = typename FwdList::iterator;
using FwdListItL = SE<FwdListIt, L>;
using FwdListItH = SE<FwdListIt, H>;
COVERT_LOG_TYPE(FwdListIt);

namespace covert {
template <>
struct type_depth<FwdListIt> : std::integral_constant<unsigned, 1> {};
} // end namespace covert

// Iterator concept requirements
static_assert(std::is_copy_constructible<FwdListIt>::value);
static_assert(std::is_copy_assignable<FwdListIt>::value);
static_assert(std::is_destructible<FwdListIt>::value);
static_assert(std::is_swappable<FwdListIt>::value);
using value_type = typename std::iterator_traits<FwdListItL>::value_type;
using difference_type =
    typename std::iterator_traits<FwdListItL>::difference_type;
using reference = typename std::iterator_traits<FwdListItL>::reference;
using pointer = typename std::iterator_traits<FwdListItL>::pointer;
using iterator_category =
    typename std::iterator_traits<FwdListItL>::iterator_category;

int main() {
  FwdList l = {3, 6, 1, 2, 3};
  SE<FwdListIt, L> li;
  SE<FwdListIt, H> hi;

  logd = &std::cout;

  TEST(li = l.begin();) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<FwdListIt, L>(FwdListIt)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(hi = l.begin();) // CHECK: TEST
  // CHECK-NEXT: Converting constructor (primitive): 'SE<FwdListIt, H>(FwdListIt)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(auto r = (hi == li);) // CHECK: TEST
  // CHECK-NEXT: SE<FwdListIt, H>, SE<FwdListIt, L>: operator=={{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'{{$}}
  // CHECK-NEXT: END TEST

  TEST(auto r = (li != li);) // CHECK: TEST
  // CHECK-NEXT: SE<FwdListIt, L>, SE<FwdListIt, L>: operator!={{$}}
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, L>(bool)'{{$}}
  // CHECK-NEXT: END TEST

  auto res = se_label_cast<bool, L>((hi != li) == !(hi == li));
  __COVERT_ASSERT__(res);

  TEST(typename std::iterator_traits<FwdListItH>::reference r = *li;) // CHECK: TEST
  // CHECK-NEXT: SE<FwdListIt, L>: Pointer dereference operator{{$}}
  // CHECK-NEXT: END TEST
}
