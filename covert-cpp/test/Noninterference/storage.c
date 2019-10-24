// RUN: not %nvt -s 8 -- DynLoader %r/%basename.out | FileCheck %s

#include "NVT.h"
#include <unistd.h>
#include <fcntl.h>

NVT_TEST_MODULE;

char c[1024];
int fd = -1;

// CHECK: Test 1 failed
NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  if (fd == -1) {
    fd = open("/dev/stdout", O_WRONLY);
  }
  int i = 0;
  for (; i < size; ++i) {
    c[i] = (char)data[i];
  }
  c[i] = '\0';
}

NVT_EXPORT void NVT_TEST_BEGIN(1)(void) { write(fd, c, sizeof(c)); }

// CHECK-NOT: Test 2 failed
NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data, unsigned size) {
  if (fd == -1) {
    fd = open("/dev/stdout", O_WRONLY);
  }
}

NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  static const char str[] = "blahhhh\n";
  write(fd, str, sizeof(str));
}

#ifdef __TEST__
int main() {
  const char data[] = "hello world";
  NVT_TEST_INIT(1)((unsigned char *)data, sizeof(data));
  NVT_TEST_BEGIN(1)();
}
#endif
