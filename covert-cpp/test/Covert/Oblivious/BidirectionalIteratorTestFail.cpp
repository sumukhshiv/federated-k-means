// RUN: %clang-syntaxo -Xclang -verify -Xclang -verify-ignore-unexpected=note %s

#include "Covert/CovertO.h"
#include "Covert/SE.h"
#include "Oblivious/oforward_list.h"

using namespace oblivious;

using List = oforward_list<SE<int, H>>;
using ListIt = typename List::iterator;

List l{0, 1, 2, 3, 4, 5, 6, 7};

int main() {
  SE<O<ListIt, List>, H> pl{{l.begin(), &l}};

  --pl; // expected-error {{cannot decrement value}}
  pl--; // expected-error {{cannot decrement value}}
}
