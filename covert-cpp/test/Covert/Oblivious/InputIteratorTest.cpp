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
    using value_type = typename std::iterator_traits<It>::value_type;
    using reference = typename std::iterator_traits<It>::reference;

    Vector v{0, 1, 2, 3, 4, 5, 6, 7};
    It i{v.begin(), &v}, _i = i;
    It j{v.end(), &v};

    { // EqualityComparable
      It a = i, b = i;
      // actually it doesn't exactly satisfy EqualityComparable;
      // `a == b` is not contextually convertible to `bool`
      assert(se_to_primitive(a == b));
      assert(se_to_primitive(!(a == j)));
    }

    {
      // Note: `i == j` is not contextually convertible to `bool`
      assert(se_to_primitive((i != j) == !(i == j)));
    }

    {
      static_assert(std::is_same_v<decltype(*i), reference>);
      static_assert(std::is_convertible_v<reference, value_type>);
      assert(se_to_primitive(*i == *_i));
    }

    // Member dereference, e.g. `i->m`, is not supported

    static_assert(std::is_same_v<decltype(++i), It &>);

    static_assert(std::is_convertible_v<decltype(*i++), value_type>);

  }

}
