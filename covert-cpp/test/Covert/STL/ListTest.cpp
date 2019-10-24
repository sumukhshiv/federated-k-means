// RUN: %clang-syntax -Xclang -verify %s
#include <list>
#include "Covert/SE.h"

// expected-no-diagnostics


int main() {
  std::list<SE<int, H>> li = {0, 1};
  std::list<SE<int, H>> li2 = {2, 3};
  li2 = li;
  li.front();
  li.back();
  li.begin();
  li.end();
  li.empty();
  li.size();
  li.max_size();
  li.clear();
  li.insert(li.end(), 2);
  li.emplace(li.end(), 2);
  li.erase(li.begin());
  li.push_back(2);
  li.emplace_back(2);
  li.pop_back();
  li.push_front(2);
  li.emplace_front(2);
  li.pop_front();
  li.resize(10);
  li.swap(li2);
  li.splice(li.end(), li2);
  li.reverse();
}
