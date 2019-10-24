//=== FixItReplacementConsumer.h - DiagnosticConsumer that replaces FixIts ===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __FIXIT_REPLACEMENT_CONSUMER_H__
#define __FIXIT_REPLACEMENT_CONSUMER_H__

#include "clang/Basic/Diagnostic.h"
#include "clang/Tooling/Core/Replacement.h"

namespace covert_tools {

/// \brief Creates and applies Replacements from FixIts attached to diagnostics.
class FixItReplacementConsumer : public clang::DiagnosticConsumer {
  using RepsMap = std::map<std::string, clang::tooling::Replacements>;

  clang::FileManager &FileMan;
  const llvm::StringRef YamlOutputFile;
  const clang::LangOptions *LangOpts;
  RepsMap Reps;

public:
  /// \param YamlOutputFile If a string value is not provided, the replacements
  /// will be written to the current source file in-place.
  FixItReplacementConsumer(clang::FileManager &,
                           const llvm::StringRef YamlOutputFile = "");
  ~FixItReplacementConsumer() = default;

  /// \brief Callback to inform the diagnostic client that processing
  /// of a source file is beginning.
  void BeginSourceFile(const clang::LangOptions &Opts,
                       const clang::Preprocessor *PP = nullptr) override;

  /// \brief If a .yaml output file was given, emit the accumulated FixIts to
  /// that file. Otherwise, write the replacements to the source file in-place.
  void finish() override;

  /// \brief Handles FixIts attached to diagnostics.
  ///
  /// For any diagnostic which has a valid \c SourceRange, create a replacement
  /// that will be applied when FixItReplacementConsumer::finish() is called.
  /// Then emit a 'FIX-IT' diagnostic message to inform the user that the
  /// replacement was applied.
  void HandleDiagnostic(clang::DiagnosticsEngine::Level DiagLevel,
                        const clang::Diagnostic &Info) override;
};

} // end namespace covert_tools

#endif
