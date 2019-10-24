// RUN: %nvt -n 2 -s 1 -- DynLoader %r/Oblivious/%basename.out

#include <cassert>
#include "NVT.h"
#include "Oblivious.h"

NVT_TEST_MODULE;

bool cond;

extern "C" NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data,
                                            unsigned size) {
  assert(size >= 1);
  cond = *data % 2;
}

struct LongString {
  char val[2055];
};
LongString S1{"ksdjf"};
LongString S2{"ksdjf"};

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  o_swap(cond, &S1, &S2, sizeof(LongString));
}

struct S {
  int val[44];
};

extern "C" NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data,
                                            unsigned size) {
  assert(size >= 1);
  cond = *data % 2;
}

S SS1, SS2;

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  o_swap_arr<44>(cond, SS1.val, SS2.val);
}

extern "C" NVT_EXPORT void NVT_TEST_INIT(3)(unsigned char *data,
                                            unsigned size) {
  assert(size >= 1);
  cond = *data % 2;
}

S _SS1, _SS2;

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(3)(void) {
  o_swap_T(cond, _SS1, _SS2);
}

extern "C" NVT_EXPORT void NVT_TEST_INIT(4)(unsigned char *data,
                                            unsigned size) {
  assert(size >= 1);
  cond = *data % 2;
}

int8_t x = 'x', y = 'y';

extern "C" NVT_EXPORT void NVT_TEST_BEGIN(4)(void) {
  o_swap_i8(cond, &x, &y);
}
