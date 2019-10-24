// RUN: %r/%basename.out
#include "oforward_list.h"

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

using ContainerT = oforward_list<Int>;
using It = O<typename ContainerT::iterator, ContainerT>;
using ConstIt = O<typename ContainerT::const_iterator, ContainerT>;
using reference = std::iterator_traits<It>::reference;
using const_reference = std::iterator_traits<ConstIt>::reference;
using value_type = std::iterator_traits<It>::value_type;
using const_value_type = std::iterator_traits<ConstIt>::value_type;

ContainerT l(8);

int main() {
  It i{l.begin(), &l};

  { // satisfies DefaultConstructible
    {It u;}
    {It u{};}
    {It();}
    {It{};}
  }

  // O does not satisfy this requirement, because it uses a proxy return object
  // static_assert(std::is_same_v<reference, value_type &>);
  // static_assert(std::is_same_v<const_reference, const_value_type &>);

  {
    static_assert(std::is_same_v<decltype(i++), It>);
    auto _i = i;
    It j = _i;
    ++_i;
    assert(i++ == j);
  }

  static_assert(std::is_same_v<decltype(*i++), reference>);

}
