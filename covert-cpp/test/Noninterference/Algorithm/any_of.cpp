// RUN: %nvt -s 9 -- DynLoader %r/Algorithm/%basename.out

#ifdef __TEST__
#include <iostream>
#endif
#include <NVT.h>
#include <cov_algorithm.h>
#include <SE.h>
#include <algorithm>
#include <forward_list>

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

SE<bool, H> ret;

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  FwdIt<L> I = fl.begin();
  FwdIt<L> E = fl.end();
  ret = covert::any_of(I, E, [](auto x) { return x == findme; });
#ifdef __TEST__
  if (se_label_cast<bool, L>(ret)) {
    std::cout << "Found '" << (int)findme << "'\n";
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
}
#endif
