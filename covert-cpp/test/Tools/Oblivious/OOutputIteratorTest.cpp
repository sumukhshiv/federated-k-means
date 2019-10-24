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
  It r{v.begin(), &v};
  Int o{3};

  *r = o;

  static_assert(std::is_same_v<decltype(++r), It &>);
  assert(&r == &++r);

  static_assert(std::is_convertible_v<decltype(r++), const It &>);

  {
    It _r = r;
    *_r = o;
    ++_r;
    *r++ = o;
    assert(_r == r);
  }

}
