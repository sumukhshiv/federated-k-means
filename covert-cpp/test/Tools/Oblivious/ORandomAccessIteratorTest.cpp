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

ContainerT l(8);

int main() {

  {
    using It = O<typename ContainerT::iterator, ContainerT>;
    using difference_type = std::iterator_traits<It>::difference_type;
    using reference = std::iterator_traits<It>::reference;

    It i{l.begin(), &l}, a = i, b = i, _r = i, &r = _r;
    difference_type n = 2;

    {
      static_assert(std::is_same_v<decltype(r += n), It &>);
      It _tmp = r;
      It &tmp = _tmp;
      difference_type m = n;
      while (m--) ++tmp;
      assert((r += n) == tmp);
    }

    {
      assert(a + n == n + a);
      static_assert(std::is_same_v<decltype(a + n), It>);
      static_assert(std::is_same_v<decltype(n + a), It>);
      {
        It temp = a;
        assert((temp += n) == a + n);
      }
      {
        It temp = a;
        assert((temp += n) == n + a);
      }
    }

    {
      It _tmp = r;
      It &tmp = _tmp;
      assert((r -= n) == (tmp += -n));
    }

    {
      static_assert(std::is_same_v<decltype(i - n), It>);
      It temp = i;
      assert(i - n == (temp -= n));
    }

    {
      It tmp = b;
      tmp += 2;
      static_assert(std::is_same_v<decltype(b - a), difference_type>);
      assert(tmp - a == 2);
    }

    {
      static_assert(std::is_convertible_v<decltype(i[n]), reference>);
      assert(i[n] == *(i + n));
    }

    {
      assert(!(a < a));
    }

    ++b;

    {
      assert(a < b);
      assert(a < b == b - a > 0);

      assert(!(a > b));
      assert(a > b == b < a);

      assert(!(a >= b));
      assert(a >= b == !(a < b));

      assert(a <= b);
      assert(a <= b == !(a > b));
    }

  }

  {
    using It = O<typename ContainerT::const_iterator, ContainerT>;
    using difference_type = std::iterator_traits<It>::difference_type;
    using reference = std::iterator_traits<It>::reference;

    It i{l.begin(), &l}, a = i, b = i, _r = i, &r = _r;
    difference_type n = 2;

    {
      static_assert(std::is_same_v<decltype(r += n), It &>);
      It _tmp = r;
      It &tmp = _tmp;
      difference_type m = n;
      while (m--) ++tmp;
      assert((r += n) == tmp);
    }

    {
      assert(a + n == n + a);
      static_assert(std::is_same_v<decltype(a + n), It>);
      static_assert(std::is_same_v<decltype(n + a), It>);
      {
        It temp = a;
        assert((temp += n) == a + n);
      }
      {
        It temp = a;
        assert((temp += n) == n + a);
      }
    }

    {
      It _tmp = r;
      It &tmp = _tmp;
      assert((r -= n) == (tmp += -n));
    }

    {
      static_assert(std::is_same_v<decltype(i - n), It>);
      It temp = i;
      assert(i - n == (temp -= n));
    }

    {
      It tmp = b;
      tmp += 2;
      static_assert(std::is_same_v<decltype(b - a), difference_type>);
      assert(tmp - a == 2);
    }

    {
      static_assert(std::is_convertible_v<decltype(i[n]), reference>);
      assert(i[n] == *(i + n));
    }

    {
      assert(!(a < a));
    }

    ++b;

    {
      assert(a < b);
      assert(a < b == b - a > 0);

      assert(!(a > b));
      assert(a > b == b < a);

      assert(!(a >= b));
      assert(a >= b == !(a < b));

      assert(a <= b);
      assert(a <= b == !(a > b));
    }

  }

}
