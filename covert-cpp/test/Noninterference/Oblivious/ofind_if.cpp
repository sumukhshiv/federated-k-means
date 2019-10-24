// RUN: %nvt -s 1 -- DynLoader %r/Oblivious/%basename.out

#include "NVT.h"
#include "oalgorithm.h"
#include "oforward_list.h"
#include "olist.h"
#include "ovector.h"
#include "oarray.h"
#include "odeque.h"

#undef NDEBUG
#include <cassert>

NVT_TEST_MODULE;

using namespace oblivious;

int idx, res;
oforward_list<int> fl(256); // forward_list with 256 nodes
olist<int> l(256); // list with 256 nodes
ovector<int> v(256); // vector with 256 slots
odeque<int> d(256); // deque with 256 slots
oarray<int, 256> a; // array with 256 slots

extern "C" {

NVT_EXPORT void NVT_TEST_INIT(1)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(1)(void) {
  int x = 0;
  auto p =
      ofind_if(fl.begin(), fl.end(), [&x](int) { return x++ == idx; }, &fl);
  assert(p != fl.end());
  res = *p;
  *p = ~res;
}

NVT_EXPORT void NVT_TEST_INIT(2)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(2)(void) {
  int x = 0;
  auto p =
      ofind_if(l.begin(), l.end(), [&x](int) { return x++ == idx; }, &l);
  assert(p != l.end());
  res = *p;
  *p = ~res;
}

NVT_EXPORT void NVT_TEST_INIT(3)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(3)(void) {
  int x = 0;
  auto p =
      ofind_if(v.begin(), v.end(), [&x](int) { return x++ == idx; }, &v);
  assert(p != v.end());
  res = *p;
  *p = ~res;
}

NVT_EXPORT void NVT_TEST_INIT(4)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(4)(void) {
  int x = 0;
  auto p =
      ofind_if(a.begin(), a.end(), [&x](int) { return x++ == idx; }, &a);
  assert(p != a.end());
  res = *p;
  *p = ~res;
}

NVT_EXPORT void NVT_TEST_INIT(5)(unsigned char *data, unsigned size) {
  assert(size >= 1);
  idx = *data;
}

NVT_EXPORT void NVT_TEST_BEGIN(5)(void) {
  int x = 0;
  auto p =
      ofind_if(d.begin(), d.end(), [&x](int) { return x++ == idx; }, &d);
  assert(p != d.end());
  res = *p;
  *p = ~res;
}
}

#ifdef __TEST__
#include <algorithm>
#include <iostream>

int main() {
  {
    std::cout << "forward_list test\n\n";
    int x = 0;
    fl.get_allocator().dump_state();
    std::for_each(fl.begin(), fl.end(), [&x](int &val) { val = x++; });
    unsigned char data[] = {0, 1, 2, 3};
    NVT_TEST_INIT(1)(data, sizeof(data));
    NVT_TEST_BEGIN(1)();
    std::cout << res << '\n';
    NVT_TEST_INIT(1)(data + 1, sizeof(data));
    NVT_TEST_BEGIN(1)();
    std::cout << res << '\n';
    NVT_TEST_INIT(1)(data + 2, sizeof(data));
    NVT_TEST_BEGIN(1)();
    std::cout << res << '\n';
    NVT_TEST_INIT(1)(data + 3, sizeof(data));
    NVT_TEST_BEGIN(1)();
    std::cout << res << '\n';
  }

  std::cout << "\n==========================\n\n";

  {
    std::cout << "list test\n\n";
    int x = 0;
    l.get_allocator().dump_state();
    std::for_each(l.begin(), l.end(), [&x](int &val) { val = x++; });
    unsigned char data[] = {0, 1, 2, 3};
    NVT_TEST_INIT(2)(data, sizeof(data));
    NVT_TEST_BEGIN(2)();
    std::cout << res << '\n';
    NVT_TEST_INIT(2)(data + 1, sizeof(data));
    NVT_TEST_BEGIN(2)();
    std::cout << res << '\n';
    NVT_TEST_INIT(2)(data + 2, sizeof(data));
    NVT_TEST_BEGIN(2)();
    std::cout << res << '\n';
    NVT_TEST_INIT(2)(data + 3, sizeof(data));
    NVT_TEST_BEGIN(2)();
    std::cout << res << '\n';
  }

  std::cout << "\n==========================\n\n";

  {
    std::cout << "vector test\n\n";
    int x = 0;
    v.get_allocator().dump_state();
    std::for_each(v.begin(), v.end(), [&x](int &val) { val = x++; });
    unsigned char data[] = {0, 1, 2, 3};
    NVT_TEST_INIT(3)(data, sizeof(data));
    NVT_TEST_BEGIN(3)();
    std::cout << res << '\n';
    NVT_TEST_INIT(3)(data + 1, sizeof(data));
    NVT_TEST_BEGIN(3)();
    std::cout << res << '\n';
    NVT_TEST_INIT(3)(data + 2, sizeof(data));
    NVT_TEST_BEGIN(3)();
    std::cout << res << '\n';
    NVT_TEST_INIT(3)(data + 3, sizeof(data));
    NVT_TEST_BEGIN(3)();
    std::cout << res << '\n';
  }

  std::cout << "\n==========================\n\n";

  {
    std::cout << "array test\n\n";
    int x = 0;
    std::for_each(a.begin(), a.end(), [&x](int &val) { val = x++; });
    unsigned char data[] = {0, 1, 2, 3};
    NVT_TEST_INIT(4)(data, sizeof(data));
    NVT_TEST_BEGIN(4)();
    std::cout << res << '\n';
    NVT_TEST_INIT(4)(data + 1, sizeof(data));
    NVT_TEST_BEGIN(4)();
    std::cout << res << '\n';
    NVT_TEST_INIT(4)(data + 2, sizeof(data));
    NVT_TEST_BEGIN(4)();
    std::cout << res << '\n';
    NVT_TEST_INIT(4)(data + 3, sizeof(data));
    NVT_TEST_BEGIN(4)();
    std::cout << res << '\n';
  }

  std::cout << "\n==========================\n\n";

  {
    std::cout << "deque test\n\n";
    int x = 0;
    d.get_allocator().dump_state();
    std::for_each(d.begin(), d.end(), [&x](int &val) { val = x++; });
    unsigned char data[] = {0, 1, 2, 3};
    NVT_TEST_INIT(5)(data, sizeof(data));
    NVT_TEST_BEGIN(5)();
    std::cout << res << '\n';
    NVT_TEST_INIT(5)(data + 1, sizeof(data));
    NVT_TEST_BEGIN(5)();
    std::cout << res << '\n';
    NVT_TEST_INIT(5)(data + 2, sizeof(data));
    NVT_TEST_BEGIN(5)();
    std::cout << res << '\n';
    NVT_TEST_INIT(5)(data + 3, sizeof(data));
    NVT_TEST_BEGIN(5)();
    std::cout << res << '\n';
  }
}
#endif
