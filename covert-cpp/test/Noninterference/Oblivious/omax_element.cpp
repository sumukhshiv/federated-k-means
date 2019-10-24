// RUN: %nvt -s 32 -- DynLoader %r/Oblivious/%basename.out

#include "NVT.h"
#include "oalgorithm.h"
#include "ovector.h"
#include "odeque.h"
#include <algorithm>

#undef NDEBUG
#include <cassert>

NVT_TEST_MODULE;

using namespace oblivious;

int idx, res;
odeque<int> d(32);  // deque with 32 slots

extern "C" {

NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  int i = 0;
  std::generate(d.begin(), d.end(), [&i, data]() { return data[i++]; });
}

NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  omax_element(d.begin(), d.end(), &d);
}
}
