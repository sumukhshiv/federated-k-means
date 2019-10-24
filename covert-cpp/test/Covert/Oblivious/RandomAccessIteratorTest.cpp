// RUN: %clang-llvmo -D__LOG_COVERT_CPP__ -Xclang -verify %s -S -o - | %opt -o %t.bc
// RUN: %llio %t.bc | %FileCheck %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/ovector.h"

#undef NDEBUG
#include <cassert>

// expected-no-diagnostics

using namespace oblivious;
using namespace covert::__covert_logging__;

using Vector = ovector<SE<int, H>>;
using VectorIt = typename Vector::iterator;
COVERT_LOG_TYPE(Vector);
COVERT_LOG_TYPE(VectorIt);

namespace covert {
template <>
struct type_depth<VectorIt> : std::integral_constant<unsigned, 1> {};
} // end namespace covert

Vector v{0, 1, 2, 3, 4, 5, 6, 7};

int main() {
  SE<O<VectorIt, Vector>, H> pv{{v.begin(), &v}};
  SE<VectorIt, H> ppv = v.begin();

  logd = &std::cout;

  TEST(pv += 1;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, int: operator+=
  // CHECK: END TEST

  TEST(auto _pv = pv + 1;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, int: operator+
  // CHECK: Converting constructor (primitive): 'SE<O<VectorIt, Vector>, H>(O<VectorIt, Vector>)'
  // CHECK: END TEST

  TEST(auto _pv = 1 + pv;); // CHECK: TEST
  // CHECK-NEXT: int, SE<O<VectorIt, Vector>, H>: operator+
  // CHECK: Converting constructor (primitive): 'SE<O<VectorIt, Vector>, H>(O<VectorIt, Vector>)'
  // CHECK: END TEST

  TEST(pv -= 1;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, int: operator-=
  // CHECK: END TEST

  TEST(auto _pv = pv - 1;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, int: operator-
  // CHECK: Converting constructor (primitive): 'SE<O<VectorIt, Vector>, H>(O<VectorIt, Vector>)'
  // CHECK: END TEST

  TEST(auto _res = pv - pv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, SE<O<VectorIt, Vector>, H>: operator-
  // CHECK-NEXT: Converting constructor (primitive): 'SE<long, H>(long)'
  // CHECK: END TEST

  TEST(auto _res = pv - ppv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, SE<VectorIt, H>: operator-
  // CHECK-NEXT: Converting constructor (primitive): 'SE<long, H>(long)'
  // CHECK: END TEST

  TEST(auto _res = ppv - pv;); // CHECK: TEST
  // CHECK-NEXT: SE<VectorIt, H>, SE<O<VectorIt, Vector>, H>: operator-
  // CHECK-NEXT: Converting constructor (primitive): 'SE<long, H>(long)'
  // CHECK: END TEST

  TEST(auto _res = pv < pv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, SE<O<VectorIt, Vector>, H>: operator<
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = pv < ppv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, SE<VectorIt, H>: operator<
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = ppv < pv;); // CHECK: TEST
  // CHECK-NEXT: SE<VectorIt, H>, SE<O<VectorIt, Vector>, H>: operator<
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = pv > pv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, SE<O<VectorIt, Vector>, H>: operator>
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = pv > ppv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, SE<VectorIt, H>: operator>
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = ppv > pv;); // CHECK: TEST
  // CHECK-NEXT: SE<VectorIt, H>, SE<O<VectorIt, Vector>, H>: operator>
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = pv <= pv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, SE<O<VectorIt, Vector>, H>: operator<=
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = pv <= ppv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, SE<VectorIt, H>: operator<=
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = ppv <= pv;); // CHECK: TEST
  // CHECK-NEXT: SE<VectorIt, H>, SE<O<VectorIt, Vector>, H>: operator<=
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = pv >= pv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, SE<O<VectorIt, Vector>, H>: operator>=
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = pv >= ppv;); // CHECK: TEST
  // CHECK-NEXT: SE<O<VectorIt, Vector>, H>, SE<VectorIt, H>: operator>=
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

  TEST(auto _res = ppv >= pv;); // CHECK: TEST
  // CHECK-NEXT: SE<VectorIt, H>, SE<O<VectorIt, Vector>, H>: operator>=
  // CHECK-NEXT: Converting constructor (primitive): 'SE<bool, H>(bool)'
  // CHECK: END TEST

}
