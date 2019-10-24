// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected %s

#include <deque>
#include "Covert/SE.h"


int main() {
  SE<bool, H> eq;
  std::deque<SE<int, H>> deq = {0, 1};
  std::deque<SE<int, H>> deq2 = {2, 3};
  eq = deq == deq2; // expected-note-re {{in instantiation of function template specialization '{{.*operator==.+}}'
}
