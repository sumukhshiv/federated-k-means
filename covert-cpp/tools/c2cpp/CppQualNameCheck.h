//=== CppQualNameCheck.h - Checks for IDs that should be qualified in C++ -===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __CPP_QUAL_NAME_CHECK_H__
#define __CPP_QUAL_NAME_CHECK_H__

#include "ICheck.h"

namespace covert_tools {
namespace c2cpp {

struct CppQualNameCheck : public ICheck {
  void run(const MatchResultT &Result) override;
  MatcherArrayT getMatchers() const override;
};

} // end namespace c2cpp
} // end namespace covert_tools

#endif
