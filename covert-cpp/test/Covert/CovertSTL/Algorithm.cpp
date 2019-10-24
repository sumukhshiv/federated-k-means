// RUN: %clang-llvmo -Xclang -verify %s -o %t.bc
// RUN: %llio %t.bc
#include "Covert/cov_algorithm.h"
#include "Covert/SE.h"
#include "Oblivious/odeque.h"

#undef NDEBUG
#include <cassert>

// expected-no-diagnostics

using namespace oblivious;

int main() {

  {
    using LDeque = odeque<SE<int, L>>;
    LDeque ld{6, 3, 4, 1, 0, 7, 5, 2};
    covert::sort(ld.begin(), ld.end());
    for (int i = 1; i < ld.size(); ++i) {
      assert(se_to_primitive(ld[i - 1] < ld[i]));
    }
  }

  {
    using HDeque = odeque<SE<int, H>>;
    HDeque hd{6, 3, 4, 1, 0, 7, 5, 2};
    covert::sort(hd.begin(), hd.end());
    for (int i = 1; i < hd.size(); ++i) {
      assert(se_to_primitive(hd[i - 1] < hd[i]));
    }
  }

  {
    using LDeque = odeque<SE<int, L>>;
    LDeque ld{6, 3, 4, 1, 0, 7, 5, 2};
    auto max = covert::max_element(ld.begin(), ld.end(), &ld);
    assert(*max == 7);
  }

  {
    using HDeque = odeque<SE<int, H>>;
    HDeque hd{6, 3, 4, 1, 0, 7, 5, 2};
    auto max = covert::max_element(hd.begin(), hd.end(), &hd);
    assert(se_to_primitive(*max == 7));
  }

}
