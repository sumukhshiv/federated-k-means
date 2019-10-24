//===------ KeywordCheck.h - Check for IDs that clash with Covert C++ -----===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __CPP2COVERT_KEYWORD_CHECK_H__
#define __CPP2COVERT_KEYWORD_CHECK_H__

#include "ICheck.h"

namespace covert_tools {
namespace cpp2covert {

/// \brief Detects and corrects identifiers which conflict with Covert C++
/// keywords.
struct KeywordCheck : public ICheck {
  void run(const MatchResultT &Result) override;
  MatcherArrayT getMatchers() const override;
};

} // end namespace cpp2covert
} // end namespace covert_tools

#endif
