// RUN: %clang-syntaxo -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/olist.h"

using namespace oblivious;

using List = olist<SE<int, H>>;
using ListIt = typename List::iterator;

List l{0, 1, 2, 3, 4, 5, 6, 7};

int main() {
  SE<O<ListIt, List>, H> pl{{l.begin(), &l}};

  pl += 4; // expected-error {{no viable overloaded '+='}}
  auto ret = pl - pl; // expected-error {{invalid operands to binary expression}}
}
