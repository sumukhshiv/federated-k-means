//== FixItReplacementConsumer.cpp - DiagnosticConsumer that replaces FixIts ==//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "clang/Frontend/FrontendDiagnostic.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/ReplacementsYaml.h"

#include "Diagnostic/FixItReplacementConsumer.h"

using namespace llvm;
using namespace clang;

namespace covert_tools {

FixItReplacementConsumer::FixItReplacementConsumer(
    FileManager &FM, const StringRef YamlOutputFile)
    : FileMan(FM), YamlOutputFile(YamlOutputFile) {}

void FixItReplacementConsumer::BeginSourceFile(const LangOptions &Opts,
                                               const Preprocessor *PP) {
  DiagnosticConsumer::BeginSourceFile(Opts, PP);
  LangOpts = &Opts;
}

void FixItReplacementConsumer::finish() {
  DiagnosticConsumer::finish();

  if (YamlOutputFile.empty()) { // write replacements in place
    LangOptions DefaultLangOptions;
    IntrusiveRefCntPtr<DiagnosticOptions> DiagOpts = new DiagnosticOptions();
    TextDiagnosticPrinter DiagnosticPrinter(llvm::errs(), DiagOpts.get());
    DiagnosticsEngine Diagnostics(
        IntrusiveRefCntPtr<DiagnosticIDs>(new DiagnosticIDs()), DiagOpts.get(),
        &DiagnosticPrinter, false);
    SourceManager SM(Diagnostics, FileMan);
    Rewriter Rewrite(SM, DefaultLangOptions);
    if (!tooling::formatAndApplyAllReplacements(Reps, Rewrite, "none")) {
      llvm::errs() << "Error: Failed to apply replacements due to conflicts\n";
    }
    if (Rewrite.overwriteChangedFiles()) {
      llvm::errs() << "Error: Failed to write fixes to file(s)\n";
    }
  } else { // Export the replacements to the given .yaml file
    std::error_code EC;
    raw_fd_ostream OS(YamlOutputFile, EC, sys::fs::F_None);
    if (EC) {
      llvm::errs() << "Error opening output file: " << EC.message() << '\n';
      exit(1);
    }

    tooling::TranslationUnitReplacements TUR;
    for (const auto &Entry : Reps) {
      TUR.Replacements.insert(TUR.Replacements.end(), Entry.second.begin(),
                              Entry.second.end());
    }

    yaml::Output YAML(OS);
    YAML << TUR;
    OS.close();
  }
}

void FixItReplacementConsumer::HandleDiagnostic(
    DiagnosticsEngine::Level DiagLevel, const Diagnostic &Info) {
  DiagnosticConsumer::HandleDiagnostic(DiagLevel, Info);
  SourceManager &SM = Info.getSourceManager();

  llvm::SmallVector<SourceLocation, 2> FixLocs;
  for (const auto &Hint : Info.getFixItHints()) {
    if (Hint.RemoveRange.isInvalid()) {
      continue;
    }

    SourceLocation BeginLoc = Hint.RemoveRange.getBegin();
    auto FileName = SM.getFilename(BeginLoc);
    if (auto Err = Reps[FileName].add(tooling::Replacement(
            SM, Hint.RemoveRange, Hint.CodeToInsert, *LangOpts))) {
      llvm::errs() << "Replacement Error: " << llvm::toString(std::move(Err))
                   << '\n';
      exit(1);
    } else {
      FixLocs.push_back(BeginLoc);
    }
  }

  // emit "FIX-IT applied" for each fixed location
  for (const auto &Loc : FixLocs) {
    DiagnosticsEngine &DE = SM.getDiagnostics();
    DE.Clear();
    DE.Report(Loc, diag::note_fixit_applied);
  }
}

} // end namespace covert_tools
