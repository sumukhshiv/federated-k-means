// RUN: %nvt -s 9 -- DynLoader %r/Algorithm/%basename.out

#ifdef __TEST__
#include <iostream>
#endif
#include "NVT.h"
#include "cov_algorithm.h"
#include "SE.h"
#include <forward_list>
#include <vector>
#include <algorithm>

NVT_TEST_MODULE;

static SE<uint8_t, L> findme;

///////
// Test Forward List

using FwdList = std::forward_list<SE<uint8_t, H>>;
template <SLabel S> using FwdIt = SE<FwdList::iterator, S>;

namespace covert {
template <>
struct type_depth<FwdList::iterator> : std::integral_constant<unsigned, 1> {};
} // end namespace covert
static FwdList fl;

extern "C" NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data,
                                            unsigned size) {
  static bool allocated = false;
  findme = *data++;

  if (!allocated) {
    fl.resize(size - 1);
    allocated = true;
  }
  std::for_each(fl.begin(), fl.end(), [&data](auto &x) { x = *data++; });
}

FwdIt<H> ret1;

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  FwdIt<L> I = fl.begin();
  FwdIt<L> E = fl.end();
  ret1 = covert::find(I, E, findme);
#ifdef __TEST__
  if (se_label_cast<bool, L>(ret1 != E)) {
    std::cout << "Found '" << (int)findme << "' at index "
              << std::distance(I, se_label_cast<FwdList::iterator, L>(ret1))
              << "\n";
  } else {
    std::cout << "Could not find '" << (int)findme << "'\n";
  }
#endif
}

///////
// Test Vector

using Vector = std::vector<SE<uint8_t, H>>;
template <SLabel S> using VecIt = SE<Vector::iterator, S>;

namespace covert {
template <>
struct type_depth<Vector::iterator> : std::integral_constant<unsigned, 1> {};
} // namespace covert

static Vector v;

extern "C" NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data,
                                            unsigned size) {
  static bool allocated = false;
  findme = *data++;

  if (!allocated) {
    v.resize(size - 1);
    allocated = true;
  }
  std::for_each(v.begin(), v.end(), [&data](auto &x) { x = *data++; });
}

VecIt<H> ret2;

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  VecIt<L> I = v.begin();
  VecIt<L> E = v.end();
  ret2 = covert::find(I, E, findme);
#ifdef __TEST__
  if (se_label_cast<bool, L>(ret2 != E)) {
    std::cout << "Found '" << (int)findme << "' at index "
              << std::distance(I, se_label_cast<Vector::iterator, L>(ret2))
              << "\n";
  } else {
    std::cout << "Could not find '" << (int)findme << "'\n";
  }
#endif
}

#ifdef __TEST__
int main() {
  unsigned char data[] = {2, 3, 6, 2, 4};
  std::cout << "==== Forward List ====\n";
  NVT_TEST_INIT(1)(data, sizeof(data));
  NVT_TEST_BEGIN(1)();
  findme = 7;
  NVT_TEST_BEGIN(1)();
  findme = 6;
  NVT_TEST_BEGIN(1)();

  std::cout << "==== Vector ====\n";
  NVT_TEST_INIT(2)(data, sizeof(data));
  NVT_TEST_BEGIN(2)();
  findme = 7;
  NVT_TEST_BEGIN(2)();
  findme = 6;
  NVT_TEST_BEGIN(2)();
}
#endif
