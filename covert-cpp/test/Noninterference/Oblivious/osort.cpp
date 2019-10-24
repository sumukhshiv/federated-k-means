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
ovector<int> v(32); // vector with 32 slots
odeque<int> d(32);  // deque with 32 slots

extern "C" {

NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  int i = 0;
  std::generate(v.begin(), v.end(), [&i, data]() { return data[i++]; });
}

NVT_EXPORT void NVT_TEST_BEGIN(1)(void) { osort(v.begin(), v.end()); }

NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data, unsigned size) {
  int i = 0;
  std::generate(d.begin(), d.end(), [&i, data]() { return data[i++]; });
}

NVT_EXPORT void NVT_TEST_BEGIN(2)(void) { osort(d.begin(), d.end()); }
}

#ifdef __TEST__
#include <iostream>

int main() {

  {
    std::cout << "vector test\n\n";
    v.resize(8);
    unsigned char data[] = {1, 0, 5, 6, 4, 3, 7, 2};
    NVT_TEST_INIT(1)(data, sizeof(data));
    NVT_TEST_BEGIN(1)();
    std::for_each(v.cbegin(), v.cend(),
                  [](const int &v) { std::cout << v << ", "; });
    std::cout << '\n';
  }

  std::cout << "\n==========================\n\n";

  {
    std::cout << "deque test\n\n";
    d.resize(8);
    unsigned char data[] = {1, 0, 5, 6, 4, 3, 7, 2};
    NVT_TEST_INIT(2)(data, sizeof(data));
    NVT_TEST_BEGIN(2)();
    std::for_each(d.cbegin(), d.cend(),
                  [](const int &v) { std::cout << v << ", "; });
    std::cout << '\n';
  }
}
#endif
