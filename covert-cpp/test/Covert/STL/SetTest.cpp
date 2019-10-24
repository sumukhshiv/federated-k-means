// RUN: %clang-syntax -Xclang -verify %s
#include <set>
#include "Covert/SE.h"

// expected-no-diagnostics


int main() {
  std::set<SE<int, H>> st;
  std::set<SE<int, H>> st2;
  st.begin();
  st.end();
  st.empty();
  st.size();
  st.max_size();
  st.clear();
  st.erase(st.begin());
  st.swap(st2);
}
