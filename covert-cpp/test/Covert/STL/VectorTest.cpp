// RUN: %clang-syntax -Xclang -verify %s
#include <vector>
#include "Covert/SE.h"

// expected-no-diagnostics


int main() {
  std::vector<SE<int, H>> vec = {0, 1};
  std::vector<SE<int, H>> vec2 = {2, 3};
  vec2 = vec;
  vec.at(1);
  vec[1];
  vec.front();
  vec.back();
  vec.begin();
  vec.end();
  vec.empty();
  vec.size();
  vec.max_size();
  vec.reserve(2);
  vec.capacity();
  vec.shrink_to_fit();
  vec.clear();
  vec.insert(vec.end(), 2);
  vec.emplace(vec.end(), 2);
  vec.erase(vec.begin());
  vec.push_back(2);
  vec.emplace_back(2);
  vec.pop_back();
  vec.resize(10);
  vec.swap(vec2);
}
