// RUN: %clang-syntax -Xclang -verify %s
#include <deque>
#include "Covert/SE.h"

// expected-no-diagnostics


int main() {
  std::deque<SE<int, H>> deq = {0, 1};
  std::deque<SE<int, H>> deq2 = {2, 3};
  deq2 = deq;
  deq.at(1);
  deq[1];
  deq.front();
  deq.back();
  deq.begin();
  deq.end();
  deq.empty();
  deq.size();
  deq.max_size();
  deq.shrink_to_fit();
  deq.clear();
  deq.insert(deq.end(), 2);
  deq.emplace(deq.end(), 2);
  deq.erase(deq.begin());
  deq.push_back(2);
  deq.emplace_back(2);
  deq.pop_back();
  deq.push_front(2);
  deq.emplace_front(2);
  deq.pop_front();
  deq.resize(10);
  deq.swap(deq2);
}
