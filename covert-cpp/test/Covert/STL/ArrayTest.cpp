// RUN: %clang-syntax -Xclang -verify %s
#include <array>
#include "Covert/SE.h"

// expected-no-diagnostics


int main() {
  std::array<SE<int, H>, 2> arr = {0, 1};
  std::array<SE<int, H>, 2> arr2 = {2, 3};
  arr2 = arr;
  arr.at(1);
  arr[1];
  arr.front();
  arr.back();
  arr.begin();
  arr.end();
  arr.empty();
  arr.size();
  arr.max_size();
  arr.fill(42);
  arr.swap(arr2);
}
