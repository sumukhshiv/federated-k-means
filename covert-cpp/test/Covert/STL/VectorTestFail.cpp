// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected %s

#include <vector>
#include "Covert/SE.h"


int main() {
  SE<bool, H> eq;
  std::vector<SE<int, H>> vec = {0, 1};
  std::vector<SE<int, H>> vec2 = {2, 3};
  eq = vec == vec2; // expected-note-re {{in instantiation of function template specialization '{{.*operator==.+}}'
}
