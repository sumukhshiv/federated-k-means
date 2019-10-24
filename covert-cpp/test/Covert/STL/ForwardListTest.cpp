// RUN: %clang-syntax -Xclang -verify %s
#include <forward_list>
#include "Covert/SE.h"

// expected-no-diagnostics


int main() {
  std::forward_list<SE<int, H>> fl = {0, 1};
  std::forward_list<SE<int, H>> fl2 = {2, 3};
  fl2 = fl;
  fl.front();
  fl.begin();
  fl.end();
  fl.empty();
  fl.max_size();
  fl.clear();
  fl.insert_after(fl.end(), 2);
  fl.emplace_after(fl.end(), 2);
  fl.erase_after(fl.begin());
  fl.push_front(2);
  fl.emplace_front(2);
  fl.pop_front();
  fl.resize(10);
  fl.swap(fl2);
  fl.splice_after(fl.end(), fl2);
  fl.reverse();
}
