//===--------- CastingCheck.cpp - Checks for errors in named casts --------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/Regex.h"

#include "CastingCheck.h"

using namespace clang;

namespace covert_tools {
namespace cpp2covert {

// FIXME: Add support for C-style casting
bool CastingCheck::match(const Diagnostic &Info) const {
  llvm::SmallString<128> DiagStr;
  Info.FormatDiagnostic(DiagStr);
  llvm::Regex R("[const|reinterpret]_cast from 'SE<.+>' (\\(aka '.+'\\))? to "
                "'.+' is not allowed");
  if (R.match(DiagStr)) {
    return true;
  }
  R = llvm::Regex("cannot cast from type 'SE<.+>' (\\(aka '.+'\\))? to .*'.+'");
  if (R.match(DiagStr)) {
    return true;
  }
  R = llvm::Regex("SE<.+>' (\\(aka '.+'\\))? is not a pointer");
  if (R.match(DiagStr)) {
    SourceManager &SM = Info.getSourceManager();
    SourceLocation EndLoc =
        Lexer::getLocForEndOfToken(Info.getLocation(), 0, SM, *LangOpts);
    CharSourceRange Range = Lexer::getAsCharRange(
        SourceRange(Info.getLocation(), EndLoc), SM, *LangOpts);
    return Lexer::getSourceText(Range, SM, *LangOpts).equals("dynamic_cast");
  }

  return false;
}

void CastingCheck::BeginSourceFile(const LangOptions &Opts,
                                   const Preprocessor *PP) {
  DiagnosticConsumerCOR::BeginSourceFile(Opts, PP);
  LangOpts = &Opts;
}

void CastingCheck::EndSourceFile() {
  DiagnosticConsumerCOR::EndSourceFile();
  LangOpts = nullptr;
}

void CastingCheck::HandleDiagnostic(DiagnosticsEngine::Level DiagLevel,
                                    const Diagnostic &Info) {
  if (!match(Info)) {
    return DiagnosticConsumerCOR::HandleDiagnostic(DiagLevel, Info);
  }

  SourceManager &SM = Info.getSourceManager();
  DiagnosticsEngine &DE = SM.getDiagnostics();

  SourceLocation BeginLoc = Info.getLocation();
  SourceLocation EndLoc =
      Lexer::getLocForEndOfToken(BeginLoc, 0, SM, *LangOpts);
  auto Range = CharSourceRange::getCharRange(BeginLoc, EndLoc);

  std::string RepCode;
  llvm::raw_string_ostream RepCodeStream(RepCode);
  RepCodeStream << "se_";
  RepCodeStream << Lexer::getSourceText(Range, SM, *LangOpts);

  const auto Fix = FixItHint::CreateReplacement(Range, RepCodeStream.str());

  DE.Clear();
  const unsigned ID =
      DE.getCustomDiagID(DiagnosticsEngine::Warning, "use '%0' instead");
  DiagnosticBuilder DB = DE.Report(BeginLoc, ID);
  DB.AddString(RepCode);
  DB.AddFixItHint(Fix);

  // Record that we handled the error
  reinterpret_cast<DiagnosticConsumerCOR *>(DE.getClient())->getNumErrors()--;
}

} // end namespace cpp2covert
} // end namespace covert_tools
