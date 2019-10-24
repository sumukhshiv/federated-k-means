#ifndef __TEST_H__
#define __TEST_H__

#ifdef __cplusplus
#include <iostream>
static std::ostream *logd;
#define TEST(...)                                                              \
  {                                                                            \
    *logd << "\nTEST: " << #__VA_ARGS__ << '\n';                               \
    { __VA_ARGS__; };                                                          \
    *logd << "END TEST\n";                                                     \
  }
#else
#include <stdio.h>
#define TEST(...)                                                              \
  {                                                                            \
    fprintf(stdout, "\nTEST: " #__VA_ARGS__ "\n");                             \
    { __VA_ARGS__; };                                                          \
    fprintf(stdout, "END TEST\n");                                             \
  }
#endif

#endif
