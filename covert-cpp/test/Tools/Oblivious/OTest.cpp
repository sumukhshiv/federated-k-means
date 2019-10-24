// RUN: %r/%basename.out
#include "../include/Test.h"
#include <iostream>
#include "ovector.h"
#include "oarray.h"

#undef NDEBUG
#include <cassert>

using namespace oblivious;

int main() {

  // functionality tests

  {
    oarray<int, 4> arr = {{{1, 2, 3, 4}}};
    O optr{arr.begin(), &arr};
    typename decltype(optr)::value_type x = optr.__get_unsafe_accessor();
    optr++;
    typename decltype(optr)::value_type y = optr.__get_unsafe_accessor();
    assert(x == 1 && y == 2);
    optr.__get_unsafe_accessor() = 7;
    assert(optr.__get_unsafe_accessor() == 7);
    assert((optr + 1).__get_unsafe_accessor() == 3);
  }

  {
    oarray<int, 4> arr = {{{1, 2, 3, 4}}};
    O optr{arr.begin(), &arr};
    typename decltype(optr)::value_type x = *optr++;
    typename decltype(optr)::value_type y = *optr;
    assert(x == 1 && y == 2);
    *optr = 7;
    assert(*optr == 7);
    assert(optr[1] == 3);
  }

  {
    oarray<int, 4> arr = {{{1, 2, 3, 4}}};
    O optr{arr.cbegin(), &arr};
    typename decltype(optr)::value_type x = *optr++;
    typename decltype(optr)::value_type y = *optr;
    assert(x == 1 && y == 2);
  }

  {
    const oarray<int, 4> arr = {{{1, 2, 3, 4}}};
    O optr{arr.cbegin(), &arr};
    typename decltype(optr)::value_type x = *optr++;
    typename decltype(optr)::value_type y = *optr;
    assert(x == 1 && y == 2);
  }

  {
    oarray<int, 4> arr = {{{1, 2, 3, 4}}};
    O optr{arr.begin(), &arr};
    typename decltype(optr)::value_type x = *optr++;
    typename decltype(optr)::value_type y = *optr;
    assert(x == 1 && y == 2);
    *optr = 7;
    assert(*optr == 7);
    assert(optr[1] == 3);
  }

  {
    ovector<int> vec = {1, 2, 3, 4};
    O optr{vec.begin(), &vec};
    typename decltype(optr)::value_type x = *optr++;
    typename decltype(optr)::value_type y = *optr;
    assert(x == 1 && y == 2);
    *optr = 7;
    assert(*optr == 7);
    assert(optr[1] == 3);
  }

  // convert non-const iterator to const iterator

  {
    using Vector = ovector<int>;
    using ConstVectorIt = typename Vector::const_iterator;
    Vector vec;
    O p{vec.begin(), &vec};
    O<ConstVectorIt, Vector> cp = p;
    assert(cp == p);
  }

}
