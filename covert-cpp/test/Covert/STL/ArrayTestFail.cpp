// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected %s

#include <array>
#include "Covert/SE.h"


int main() {
  SE<bool, H> eq;
  std::array<SE<int, H>, 2> arr = {0, 1};
  std::array<SE<int, H>, 2> arr2 = {2, 3};
  eq = arr == arr2; // expected-note-re {{in instantiation of function template specialization '{{.*operator==.+}}'
}
