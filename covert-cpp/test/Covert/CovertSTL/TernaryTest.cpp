// RUN: %clang-llvmo -D__LOG_COVERT_CPP__ -Xclang -verify %s -o %t.bc
// RUN: %llio %t.bc | %FileCheck %s
#include "Covert/cov_algorithm.h"
#include "Covert/SE.h"

// expected-no-diagnostics

using namespace covert::__covert_logging__;

struct S {
  int i;
  void *p;
  short s;
  double d;
  char c;

  void print(std::ostream *out) const {
    *out << i << ", " << (intptr_t)p << ", " << s << ", " << d << ", " << c << '\n';
  }
};

namespace covert {
template <>
struct type_depth<S> : std::integral_constant<unsigned, 1> {};
} // end namespace covert
COVERT_LOG_TYPE(S);

struct S2 {
  uint64_t a;
  uint32_t b;
};

namespace covert {
template <>
struct type_depth<S2> : std::integral_constant<unsigned, 1> {};
} // end namespace covert
COVERT_LOG_TYPE(S2);

int main() {
  logd = &std::cout;

  SE<S, H> s1{{42, nullptr, 7, 4.2, 'c'}};
  SE<S, H> s2{{2, (void *)1, 3, 4.3, 'd'}};
  SE<S, H> s3;
  S &_s3 = se_to_primitive(s3);
  SE<bool, H> c;

  TEST(c = true; s3 = covert::ternary(c, s1, s2); _s3.print(logd);)  // CHECK: TEST
  // CHECK: 42, 0, 7, 4.2, c
  // CHECK: END TEST

  TEST(c = false; s3 = covert::ternary(c, s1, s2); _s3.print(logd);) // CHECK: TEST
  // CHECK: 2, 1, 3, 4.3, d
  // CHECK: END TEST

  {
    SE<uint32_t, H> x, y = 12, z = 23;
    uint32_t &_x = se_to_primitive(x);
    TEST(c = true; x = covert::ternary(c, y, z); std::cout << _x << '\n';)  // CHECK: TEST
    // CHECK: 12
    // CHECK: END TEST

    TEST(c = false; x = covert::ternary(c, y, z); std::cout << _x << '\n';) // CHECK: TEST
    // CHECK: 23
    // CHECK: END TEST
  }

  {
    SE<uint64_t, H> x, y = 12, z = 23;
    uint64_t &_x = se_to_primitive(x);
    TEST(c = true; x = covert::ternary(c, y, z); std::cout << _x << '\n';)  // CHECK: TEST
    // CHECK: 12
    // CHECK: END TEST

    TEST(c = false; x = covert::ternary(c, y, z); std::cout << _x << '\n';) // CHECK: TEST
    // CHECK: 23
    // CHECK: END TEST
  }

  {
    SE<S2, H> x, y = {{2, 12}}, z = {{23, 4}};
    S2 &_x = se_to_primitive(x);
    TEST(c = true; x = covert::ternary(c, y, z); std::cout << _x.a << ", " << _x.b << '\n';)  // CHECK: TEST
    // CHECK: 2, 12
    // CHECK: END TEST

    TEST(c = false; x = covert::ternary(c, y, z); std::cout << _x.a << ", " << _x.b << '\n';) // CHECK: TEST
    // CHECK: 23, 4
    // CHECK: END TEST
  }
}
