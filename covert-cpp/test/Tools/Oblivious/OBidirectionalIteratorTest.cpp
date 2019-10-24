// RUN: %r/%basename.out
#include "olist.h"

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

using ContainerT = olist<Int>;
using It = O<typename ContainerT::iterator, ContainerT>;
using reference = std::iterator_traits<It>::reference;
using value_type = std::iterator_traits<It>::value_type;

ContainerT l(8);

int main() {
  It a{l.begin(), &l};
  ++a, ++a, ++a, ++a;
  It b = a;

  {
    static_assert(std::is_same_v<decltype(--a), It &>);
    assert(--(++a) == a);
    assert(a == b && --a == --b);
    assert(&a == &--a);
  }

  static_assert(std::is_convertible_v<decltype(a--), const It &>);

  static_assert(std::is_same_v<decltype(*a--), reference>);

}
