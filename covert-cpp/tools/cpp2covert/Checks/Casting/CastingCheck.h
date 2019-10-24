//===---------- CastingCheck.h - Checks for errors in named casts ---------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __CPP2COVERT_CASTING_CHECK_H__
#define __CPP2COVERT_CASTING_CHECK_H__

#include "Diagnostic/DiagnosticConsumerCOR.h"

namespace covert_tools {
namespace cpp2covert {

/// \brief Intercepts diagnostics about casting errors.
///
/// After refactoring from C++ to Covert C++, some explicit casts may no longer
/// be valid. This "check" intercepts diagnostic messages about bad casts, and
/// determines whether a given bad cast can be resolved by refactoring to an
/// 'se_*_cast'.
class CastingCheck : public DiagnosticConsumerCOR {
  const clang::LangOptions *LangOpts;

  bool match(const clang::Diagnostic &Info) const;

public:
  CastingCheck(std::unique_ptr<DiagnosticConsumerCOR> Next)
      : DiagnosticConsumerCOR(std::move(Next)), LangOpts(nullptr) {}
  ~CastingCheck() {}

  void BeginSourceFile(const clang::LangOptions &Opts,
                       const clang::Preprocessor *PP = nullptr) override;
  void EndSourceFile() override;
  void HandleDiagnostic(clang::DiagnosticsEngine::Level DiagLevel,
                        const clang::Diagnostic &Info) override;
};

} // end namespace cpp2covert
} // end namespace covert_tools

#endif
