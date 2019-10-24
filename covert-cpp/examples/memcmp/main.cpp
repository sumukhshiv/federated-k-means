//===---- examples/memcmp/main.cpp - An example of Covert C++ memcmp() ----===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "memcmp.h"
#include <iostream>

/**
 * \defgroup EXAMPLES_MEMCMP Memory Compare
 * \ingroup EXAMPLES
 * \brief Covert C++ `memcmp()` example.
 *
 * This example is fully explained in Part 2 of the
 * [Tutorial](docs/Tutorial.md).
 *
 * **Note:** The source code for this tutorial can be found in
 * `examples/memcmp/`. It can be built by making the `example-memcmp-run`
 * target.
 */

int main() {
  const SE<std::size_t, L> sz = 128;
  SE<const char *, L, H> secret = "This is the secret";
  SE<const char *, L, L> input = "This is NOT the secret";
  auto _secret = se_reinterpret_cast<const uint8_t *, L, H>(secret);
  auto _input = se_reinterpret_cast<const uint8_t *, L, L>(input);

  std::cout << "Testing with secret input...\n";
  if (se_label_cast<bool, L>(!memcmp(_secret, _input, sz))) {
    std::cout << "You got it!\n";
  } else {
    std::cout << "You didn't get it!\n";
  }

  std::cout << "\n--------------------------\n\n";

  std::cout << "Testing with public input...\n";
  auto _disclosed_secret = se_label_cast<const uint8_t *, L, L>(_secret);
  if (!memcmp(_disclosed_secret, _input, sz)) {
    std::cout << "You got it!\n";
  } else {
    std::cout << "You didn't get it!\n";
  }
  return 0;
}
