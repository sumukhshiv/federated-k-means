// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected %s

#include <set>
#include "Covert/SE.h"


int main() {
  SE<bool, H> eq;
  std::set<SE<int, H>> st;
  std::set<SE<int, H>> st2;
  st.insert(2); // expected-note-re {{in instantiation of member function '{{.+insert}}'}}
}
