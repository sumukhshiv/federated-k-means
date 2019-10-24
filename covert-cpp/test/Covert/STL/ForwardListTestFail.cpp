// RUN: %clang-syntax -Xclang -verify -Xclang -verify-ignore-unexpected %s

#include <forward_list>
#include "Covert/SE.h"


int main() {
  SE<bool, H> eq;
  std::forward_list<SE<int, H>> fl = {0, 1};
  std::forward_list<SE<int, H>> fl2 = {2, 3};
  eq = fl == fl2; // expected-note-re {{in instantiation of function template specialization '{{.*operator==.+}}'
  fl.sort(); // expected-note-re {{in instantiation of member function '{{.+sort}}'}}
  fl.unique(); // expected-note-re {{in instantiation of member function '{{.+unique}}'}}
  fl.remove(4); // expected-note-re {{in instantiation of member function '{{.+remove}}'}}
  fl.remove_if([](const SE<int, H> &) -> SE<bool, H> { return true; }); // expected-note-re {{in instantiation of function template specialization '{{.+remove_if.+}}'}}
  fl.merge(fl2); // same error as fl.sort()
}
