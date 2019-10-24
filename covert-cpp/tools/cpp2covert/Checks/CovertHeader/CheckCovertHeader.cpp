//===--- CheckCovertHeader.cpp - Checks for a missing Covert.h include ----===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "clang/Frontend/TextDiagnosticPrinter.h"

#include "CheckCovertHeader.h"
#include "Diagnostic/DiagnosticConsumerCOR.h"
#include "Diagnostic/FixItReplacementConsumer.h"

using namespace clang;

namespace covert_tools {
namespace cpp2covert {

static void EmitCovertHeaderDiagnostic(DiagnosticsEngine &DE,
                                       bool LinkedWithCovert) {
  const SourceManager &SM = DE.getSourceManager();
  const std::string HeaderName = "SE.h";
  const std::string HeaderPath = LinkedWithCovert ? "" : "Covert/";
  const std::string Fix = "#include \"" + HeaderPath + HeaderName + "\"\n";
  SourceLocation Loc = SM.getLocForStartOfFile(SM.getMainFileID());
  const unsigned ID = DE.getCustomDiagID(DiagnosticsEngine::Warning,
                                         "Could not find header file '%0'");
  DiagnosticBuilder DB = DE.Report(Loc, ID);
  DB << HeaderName << FixItHint::CreateInsertion(Loc, Fix);
}

static bool FindCovertHeader(const ASTContext &Ctx) {
  const SourceManager &SM = Ctx.getSourceManager();
  const TranslationUnitDecl *TUD = Ctx.getTranslationUnitDecl();

  for (auto &d : TUD->decls()) {
    if (auto *NS = dyn_cast<NamespaceDecl>(d)) {
      if (NS->getName() == "covert") {
        for (auto &d : NS->decls()) {
          if (auto *NS = dyn_cast<NamespaceDecl>(d)) {
            if (NS->getName() == "se") {
              llvm::StringRef FileName =
                  SM.getFilename(SM.getSpellingLoc(NS->getLocation()));
              if (FileName.endswith("SE.h")) {
                return true;
              }
            }
          }
        }
      }
    }
  }

  return false;
}

bool CheckCovertHeader(ASTContext &Ctx, bool LinkedWithCovert) {
  if (FindCovertHeader(Ctx)) {
    return true;
  }

  // Could not find the Covert C++ header. Emit a diagnostic!
  DiagnosticsEngine &DE = Ctx.getDiagnostics();
  EmitCovertHeaderDiagnostic(DE, LinkedWithCovert);

  return false;
}

} // namespace cpp2covert
} // namespace covert_tools
