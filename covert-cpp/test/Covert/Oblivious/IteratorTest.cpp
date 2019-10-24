// RUN: %clang-llvmo -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %llio %t.bc

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/ovector.h"

#undef NDEBUG
#include <cassert>

// expected-no-diagnostics

using namespace oblivious;

using Vector = ovector<SE<int, H>>;
using VectorIt = typename Vector::iterator;

int main() {

  {
    using It = SE<O<VectorIt, Vector>, H>;

    // satisfies std::iterator_traits<It> interface
    using value_type = typename std::iterator_traits<It>::value_type;
    static_assert(std::is_same_v<value_type, SE<int, H>>);
    using difference_type = typename std::iterator_traits<It>::difference_type;
    static_assert(std::is_same_v<difference_type, SE<std::ptrdiff_t, L>>);
    using reference = typename std::iterator_traits<It>::reference;
    static_assert(std::is_same_v<reference, decltype(*std::declval<It &>())>);
    using pointer = typename std::iterator_traits<It>::pointer;
    static_assert(std::is_same_v<pointer, SE<int *, H, H>>);
    using iterator_category = typename std::iterator_traits<It>::iterator_category;
    static_assert(std::is_same_v<iterator_category, std::random_access_iterator_tag>);

    Vector v{0, 1, 2, 3, 4, 5, 6, 7};
    It t{v.begin(), &v};

    { // satisfies MoveConstructible
      It u = std::move(t);
      assert(se_to_primitive(u == t));
      It w(std::move(t));
      assert(se_to_primitive(w == t));
    }

    { // satisfies CopyConstructible
      It u = t;
      assert(se_to_primitive(u == t));
      It w(t);
      assert(se_to_primitive(w == t));
    }

    { // satisfies MoveAssignable
      It u{v.end(), &v};
      static_assert(std::is_same_v<decltype(u = std::move(t)), It &>);
      u = std::move(t);
      assert(se_to_primitive(u == t));
    }

    { // satisfies CopyAssignable
      It u{v.end(), &v};
      static_assert(std::is_same_v<decltype(u = t), It &>);
      u = t;
      assert(se_to_primitive(u == t));
    }

    { // satisfies Destructible
      It u{v.end(), &v};
      u.~It();
    }

    { // satisfies Swappable
      using std::swap;
      It u{v.end(), &v};
      assert(se_to_primitive(u != t));
      It _t = t, _u = u;
      swap(u, t);
      assert(se_to_primitive(u == _t) && se_to_primitive(t == _u));
    }
  }

  {
    using It = SE<O<VectorIt, Vector>, L>;

    // satisfies std::iterator_traits<It> interface
    using value_type = typename std::iterator_traits<It>::value_type;
    static_assert(std::is_same_v<value_type, SE<int, H>>);
    using difference_type = typename std::iterator_traits<It>::difference_type;
    static_assert(std::is_same_v<difference_type, SE<std::ptrdiff_t, L>>);
    using reference = typename std::iterator_traits<It>::reference;
    static_assert(std::is_same_v<reference, decltype(*std::declval<It &>())>);
    using pointer = typename std::iterator_traits<It>::pointer;
    static_assert(std::is_same_v<pointer, SE<int *, L, H>>);
    using iterator_category = typename std::iterator_traits<It>::iterator_category;
    static_assert(std::is_same_v<iterator_category, std::random_access_iterator_tag>);

    Vector v{0, 1, 2, 3, 4, 5, 6, 7};
    It t{v.begin(), &v};

    { // satisfies MoveConstructible
      It u = std::move(t);
      assert(se_to_primitive(u == t));
      It w(std::move(t));
      assert(se_to_primitive(w == t));
    }

    { // satisfies CopyConstructible
      It u = t;
      assert(se_to_primitive(u == t));
      It w(t);
      assert(se_to_primitive(w == t));
    }

    { // satisfies MoveAssignable
      It u{v.end(), &v};
      static_assert(std::is_same_v<decltype(u = std::move(t)), It &>);
      u = std::move(t);
      assert(se_to_primitive(u == t));
    }

    { // satisfies CopyAssignable
      It u{v.end(), &v};
      static_assert(std::is_same_v<decltype(u = t), It &>);
      u = t;
      assert(se_to_primitive(u == t));
    }

    { // satisfies Destructible
      It u{v.end(), &v};
      u.~It();
    }

    { // satisfies Swappable
      using std::swap;
      It u{v.end(), &v};
      assert(se_to_primitive(u != t));
      It _t = t, _u = u;
      swap(u, t);
      assert(se_to_primitive(u == _t) && se_to_primitive(t == _u));
    }
  }

}
