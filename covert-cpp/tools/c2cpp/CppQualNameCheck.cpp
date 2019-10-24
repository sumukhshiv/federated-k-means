//=== CppQualNameCheck.cpp - Checks for IDs that should be qualified in C++ ==//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "CppQualNameCheck.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace clang::ast_matchers;

namespace covert_tools {
namespace c2cpp {

ICheck::MatcherArrayT CppQualNameCheck::getMatchers() const {
  static const ICheck::MatcherT Matchers[] = {
      loc(qualType(
              anyOf(enumType(hasDeclaration(enumDecl().bind("TagDecl"))),
                    recordType(hasDeclaration(recordDecl().bind("TagDecl"))))))
          .bind("TypeLoc"),
      declRefExpr(hasDeclaration(enumConstantDecl(
                                     hasDeclContext(enumDecl().bind("TagDecl")))
                                     .bind("EnumConstantDecl")))
          .bind("DeclRefExpr")};
  return Matchers;
}

void CppQualNameCheck::run(const MatchFinder::MatchResult &Result) {
  auto TD = Result.Nodes.getNodeAs<TagDecl>("TagDecl");
  assert(TD);

  SourceManager &SM = *Result.SourceManager;
  ASTContext &Ctx = *Result.Context;
  DiagnosticsEngine &DE = Ctx.getDiagnostics();

  SourceLocation StartLoc;
  std::string Name;
  if (auto TL = Result.Nodes.getNodeAs<TypeLoc>("TypeLoc")) {
    StartLoc = TL->getUnqualifiedLoc().getBeginLoc();
    Name = TD->getNameAsString();
    if (StartLoc == TD->getLocation()) {
      return;
    }
  } else if (auto DRE = Result.Nodes.getNodeAs<DeclRefExpr>("DeclRefExpr")) {
    StartLoc = DRE->getBeginLoc();
    auto ECD = Result.Nodes.getNodeAs<EnumConstantDecl>("EnumConstantDecl");
    assert(ECD);
    Name = ECD->getNameAsString();
  } else {
    assert(false && "CppQualNameCheck: invalid match");
  }
  SourceLocation EndLoc =
      Lexer::getLocForEndOfToken(StartLoc, 1, SM, Ctx.getLangOpts());

  llvm::SmallVector<llvm::StringRef, 4> scope_names;
  const DeclContext *DC = TD->getLexicalDeclContext();
  while (const auto *RD = dyn_cast<RecordDecl>(DC)) {
    scope_names.push_back(RD->getName());
    DC = RD->getLexicalDeclContext();
  }
  if (scope_names.empty())
    return;

  std::string QualName = "";
  while (!scope_names.empty()) {
    QualName += scope_names.pop_back_val().str();
    QualName += "::";
  }
  QualName += Name;
  SourceRange Range(StartLoc, EndLoc);

  {
    const unsigned ID = DE.getCustomDiagID(DiagnosticsEngine::Warning,
                                           "'%0' must be qualified in C++");
    auto DiagBuilder = DE.Report(StartLoc, ID);
    DiagBuilder.AddString(Name);
    auto Fix = FixItHint::CreateReplacement(Range, QualName);
    DiagBuilder.AddFixItHint(Fix);
  }
  if (Range.isInvalid()) {
    const unsigned ID =
        DE.getCustomDiagID(DiagnosticsEngine::Note, "use '%0' instead");
    auto DiagBuilder = DE.Report(SM.getSpellingLoc(StartLoc), ID);
    DiagBuilder.AddString(QualName);
  }
}

} // end namespace c2cpp
} // end namespace covert_tools
