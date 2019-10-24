// RUN: %nvt -n 2 -s 1 -- DynLoader %r/%basename.out

#ifdef __TEST__
#include <iostream>
#endif
#include <cassert>
#include "NVT.h"
#include "cov_algorithm.h"
#include "SE.h"
#include <cstring>

NVT_TEST_MODULE;

SE<bool, H> cond;
struct alignas(int) LongString {
  char val[2048];
  LongString() = default;
  LongString(const char *str) {
    strncpy(val, str, 2048);
  }
};

namespace covert {
template <> struct type_depth<LongString> : std::integral_constant<unsigned, 1> {};
} // end namespace covert

extern "C" NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data,
                                            unsigned size) {
  assert(size >= 1);
  cond = *data % 2;
}

SE<LongString, H> S1{"This string is exactly 48 characters!!!!!!!"};
SE<LongString, H> S2{"This_string is exactly 48 characters@@@@@@@"};
SE<LongString, H> res;

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  res = ternary(cond, S1, S2);
#ifdef __TEST__
  std::cout << se_to_primitive(res).val << '\n';
#endif
}

struct alignas(int) S {
  char val[44];
  S() = default;
  S(const char *str) {
    strncpy(val, str, 44);
  }
};

namespace covert {
template <> struct type_depth<S> : std::integral_constant<unsigned, 1> {};
} // end namespace covert

extern "C" NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data,
                                            unsigned size) {
  assert(size >= 1);
  cond = *data % 2;
}

SE<S, H> SS1{"This string is"};
SE<S, H> SS2{"This_string_is"};
SE<S, H> _res;

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  _res = ternary(cond, SS1, SS2);
}

#ifdef __TEST__
int main() {
  unsigned char data[] = {1, 0};
  NVT_TEST_INIT(1)(data, 1);
  NVT_TEST_BEGIN(1)();
  NVT_TEST_INIT(1)(data + 1, 1);
  NVT_TEST_BEGIN(1)();
}
#endif
