// RUN: %r/%basename.out
#include "ovector.h"

#undef NDEBUG
#include <cassert>

using namespace oblivious;

struct Int {
  int m;
  Int() : m(0) {}
  Int(int x) : m(x) {}
  inline operator int &() { return m; }
};
inline bool operator==(Int x, Int y) { return x.m == y.m; }

using ContainerT = ovector<Int>;
using It = O<typename ContainerT::iterator, ContainerT>;
using reference = std::iterator_traits<It>::reference;
using value_type = std::iterator_traits<It>::value_type;

ContainerT v(8);

int main() {
  It i{v.begin(), &v};
  It j = i, k = j;

  { // satisfies EqualityComparable
    assert(k == i && i == k);
    assert(i == j);
  }

  assert((i != j) == !(i == j));

  static_assert(std::is_same_v<decltype(*i), reference>);
  static_assert(std::is_convertible_v<reference, value_type>);
  assert(*i == *j);
  assert(((void)*i, *i) == *i);

  // O does not currently support member access
  // assert(i->m == (*i).m);

  static_assert(std::is_same_v<decltype(++i), It &>);

  {
    static_assert(std::is_convertible_v<decltype(*i++), value_type>);
    It _i = i, _j = j;
    value_type x = *_j;
    ++_j;
    assert(*_i++ == x);
  }

}
