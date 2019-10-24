//===--- TypeCheck.h - Find primitive types and refactor to covert types --===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __CPP2COVERT_TYPE_CHECK_H__
#define __CPP2COVERT_TYPE_CHECK_H__

#include "ICheck.h"

namespace covert_tools {
namespace cpp2covert {

/// \brief Like a clang \c PrintingPolicy, but with options specific to Covert
/// C++.
struct CovertTypeCheckPolicy : clang::PrintingPolicy {
  uint32_t UseCovertQualifier : 1;
  uint32_t RewriteSecretOnly : 1;
  uint32_t LinkedWithCovert : 1;
  uint32_t unused : 29;

  CovertTypeCheckPolicy();
};

/// \brief Converts primitive types into SE types.
class CovertTypeCheck : public ICheck {
  clang::ast_matchers::MatchFinder::MatchCallback *impl;

public:
  CovertTypeCheck(CovertTypeCheckPolicy Policy,
                  llvm::ArrayRef<std::string> QualifierRemovalPatterns = {});
  ~CovertTypeCheck();

  void onStartOfTranslationUnit() override;
  void run(const MatchResultT &Result) override;
  MatcherArrayT getMatchers() const override;
};

} // end namespace cpp2covert
} // end namespace covert_tools

#endif
