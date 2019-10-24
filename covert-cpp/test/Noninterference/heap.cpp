// RUN: %nvt -s 1 -- DynLoader %r/%basename.out

#include "NVT.h"
#include "ovector.h"

NVT_TEST_MODULE;

int val, res, *p, *q;

extern "C" NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data,
                                            unsigned size) {
  val = *data;
}

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  p = new int[256];
  for (int i = 0; i < 256; ++i) {
    p[i] = val;
  }
  q = new int[256];
  for (int i = 0; i < 256; ++i) {
    q[i] = val + 1;
  }
  delete[] p;
  delete[] q;
}

extern "C" NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data,
                                            unsigned size) {
  val = *data;
}

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  std::vector<int> v(256);
  for (int i = 0; i < 256; ++i) {
    v[i] = val;
  }
  res = 0;
  for (int i = 0; i < 256; ++i) {
    res += v[i];
  }
}

extern "C" NVT_EXPORT void NVT_TEST_INIT(3)(unsigned char *data,
                                            unsigned size) {
  val = *data;
}

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(3)(void) {
  oblivious::ovector<int> v(256);
  for (int i = 0; i < 256; ++i) {
    v[i] = val;
  }
  res = 0;
  for (int i = 0; i < 256; ++i) {
    res += v[i];
  }
}

#ifdef __TEST__
int main() {
  unsigned char data = 42;
  NVT_TEST_INIT(3)(&data, 1);
  NVT_TEST_BEGIN(3)();
}
#endif
