// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected %s

#include <list>
#include "Covert/SE.h"


int main() {
  SE<bool, H> eq;
  std::list<SE<int, H>> li = {0, 1};
  std::list<SE<int, H>> li2 = {2, 3};
  li.sort(); // expected-note-re {{in instantiation of member function '{{.+sort}}'}}
  li.unique(); // expected-note-re {{in instantiation of member function '{{.+unique}}'}}
  li.remove(4); // expected-note-re {{in instantiation of member function '{{.+remove}}'}}
}
