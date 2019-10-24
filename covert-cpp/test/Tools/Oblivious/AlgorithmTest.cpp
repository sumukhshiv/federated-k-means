// RUN: %r/%basename.out
#include "../include/Test.h"
#include "oalgorithm.h"
#include "oforward_list.h"
#include "ovector.h"

#undef NDEBUG
#include <cassert>

using namespace oblivious;

template <typename T>
bool is_sorted(const T &container) {
  using Iter = typename T::const_iterator;
  Iter I = container.cbegin(), N = I;
  ++N;
  for (; N != container.cend(); ++I, ++N) {
    if (*I > *N) {
      return false;
    }
  }
  return true;
}

int main() {

  { // ofind_if()
    using C = oforward_list<int>;
    using CC = oforward_list<int>;
    using CI = typename C::iterator;
    using CCI = typename C::const_iterator;
    C l = {4, 1, 2, 6, 5, 3, 7, 0};
    O<CCI, C> co =
        ofind_if(l.cbegin(), l.cend(), [](int x) { return x > 5; }, &l);
    assert(*co == 6);

    O<CI, C> o = ofind_if(l.begin(), l.end(), [](int x) { return x < 4; }, &l);
    assert(*o == 1);
    CC cl = {4, 1, 2, 6, 5, 3, 7, 0};
    *o = -1;
    assert(*o == -1);
    O<CCI, CC> cco =
        ofind_if(l.cbegin(), l.cend(), [](int x) { return x > 5; }, &l);
    assert(*cco == 6);
  }

  { // osort()
    using C = ovector<int>;
    C v = {4, 1, 2, 6, 5, 3, 7, 0};
    osort(v.begin(), v.end());
    assert(is_sorted(v));
  }

  { // max_element()
    using C = ovector<int>;
    C v = {4, 1, 2, 6, 5, 3, 6, 0};
    auto m = omax_element(v.cbegin(), v.cend(), &v);
    assert(m - v.cbegin() == 3);
  }

}
