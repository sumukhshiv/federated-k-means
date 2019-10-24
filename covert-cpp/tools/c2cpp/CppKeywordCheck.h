//===--------- CppKeywordCheck.h - Checks C code for C++ keywords ---------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __CPP_KEYWORD_CHECK_H__
#define __CPP_KEYWORD_CHECK_H__

#include "ICheck.h"

namespace covert_tools {
namespace c2cpp {

struct CppKeywordCheck : public ICheck {
  void run(const MatchResultT &Result) override;
  MatcherArrayT getMatchers() const override;
};

} // end namespace c2cpp
} // end namespace covert_tools

#endif
