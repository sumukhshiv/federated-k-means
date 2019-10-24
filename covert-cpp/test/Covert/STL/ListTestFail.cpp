// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected %s

#include <list>
#include "Covert/SE.h"


int main() {
  SE<bool, H> eq;
  std::list<SE<int, H>> li = {0, 1};
  std::list<SE<int, H>> li2 = {2, 3};
  eq = li == li2; // expected-note-re {{in instantiation of function template specialization '{{.*operator==.+}}'
  li.remove_if([](const SE<int, H> &) -> SE<bool, H> { return true; }); // expected-note-re {{in instantiation of function template specialization '{{.+remove_if.+}}'}}
  li.merge(li2); // expected-note-re {{in instantiation of member function '{{.+merge}}'}}
}
