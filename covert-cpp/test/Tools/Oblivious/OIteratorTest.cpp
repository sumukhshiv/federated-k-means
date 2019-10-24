// RUN: %r/%basename.out
#include "ovector.h"

#undef NDEBUG
#include <cassert>

using namespace oblivious;

using ContainerT = ovector<int>;
using It = O<typename ContainerT::iterator, ContainerT>;

// satisfies std::iterator_traits<It> interface
using value_type = typename std::iterator_traits<It>::value_type;
using difference_type = typename std::iterator_traits<It>::difference_type;
using reference = typename std::iterator_traits<It>::reference;
using pointer = typename std::iterator_traits<It>::pointer;
using iterator_category = typename std::iterator_traits<It>::iterator_category;

ovector<int> v{0, 1, 2, 3, 4, 5, 6, 7};

int main() {
  It t{v.begin(), &v};

  { // satisfies MoveConstructible
    It u = std::move(t);
    assert(u == t);
    It w(std::move(t));
    assert(w == t);
  }

  { // satisfies CopyConstructible
    It u = t;
    assert(u == t);
    It w(t);
    assert(w == t);
  }

  { // satisfies MoveAssignable
    It u{v.end(), &v};
    static_assert(std::is_same_v<decltype(u = std::move(t)), It &>);
    u = std::move(t);
    assert(u == t);
  }

  { // satisfies CopyAssignable
    It u{v.end(), &v};
    static_assert(std::is_same_v<decltype(u = t), It &>);
    u = t;
    assert(u == t);
  }

  { // satisfies Destructible
    It u{v.end(), &v};
    u.~It();
  }

  { // satisfies Swappable
    using std::swap;
    It u{v.end(), &v};
    assert(u != t);
    It _t = t, _u = u;
    swap(u, t);
    assert(u == _t && t == _u);
  }

}
