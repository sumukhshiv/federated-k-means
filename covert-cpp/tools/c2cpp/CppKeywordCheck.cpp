//===-------- CppKeywordCheck.cpp - Checks C code for C++ keywords --------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "CppKeywordCheck.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/StringSet.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::ast_matchers::internal;

namespace covert_tools {
namespace c2cpp {

/// Matches named decls that are C++ keywords, but not C keywords.
AST_MATCHER(NamedDecl, isCppKeyword) {
  static const llvm::StringSet<> Keywords = {
      "asm",         "dynamic_cast",
      "namespace",   "reinterpret_cast",
      "try",         "bool",
      "explicit",    "new",
      "static_cast", "typeid",
      "catch",       "false",
      "operator",    "template",
      "typename",    "class",
      "friend",      "private",
      "this",        "using",
      "const_cast",  "inline",
      "public",      "throw",
      "virtual",     "delete",
      "mutable",     "protected",
      "true",        /*"wchar_t",*/ "and",
      "bitand",      "compl",
      "not_eq",      "or_eq",
      "xor_eq",      "and_eq",
      "bitor",       "not",
      "or",          "xor",
  };

  if (const IdentifierInfo *ID = Node.getIdentifier()) {
    return Keywords.find(ID->getName()) != Keywords.end();
  }

  return false;
}

ICheck::MatcherArrayT CppKeywordCheck::getMatchers() const {
  static const DeclarationMatcher KeywordDeclMatcher =
      namedDecl(isCppKeyword(), unless(isImplicit())).bind("KeywordDecl");
  static const ICheck::MatcherT Matchers[] = {
      KeywordDeclMatcher,
      loc(qualType(hasDeclaration(KeywordDeclMatcher))).bind("type"),
      expr(anyOf(declRefExpr(hasDeclaration(KeywordDeclMatcher)).bind("expr"),
                 memberExpr(hasDeclaration(KeywordDeclMatcher)).bind("expr")))};
  return Matchers;
}

void CppKeywordCheck::run(const MatchResultT &Result) {
  auto ND = Result.Nodes.getNodeAs<NamedDecl>("KeywordDecl");
  assert(ND);

  SourceManager &SM = *Result.SourceManager;
  ASTContext &Ctx = *Result.Context;
  DiagnosticsEngine &DE = Ctx.getDiagnostics();

  SourceLocation StartLoc;
  if (auto TL = Result.Nodes.getNodeAs<TypeLoc>("type")) {
    StartLoc = TL->getUnqualifiedLoc().getBeginLoc();
  } else if (auto E = Result.Nodes.getNodeAs<Expr>("expr")) {
    if (auto CE = dyn_cast<const CallExpr>(E)) {
      StartLoc = CE->getBeginLoc();
    } else if (auto DRE = dyn_cast<const DeclRefExpr>(E)) {
      StartLoc = DRE->getBeginLoc();
    } else if (auto ME = dyn_cast<const MemberExpr>(E)) {
      StartLoc = ME->getMemberLoc();
    } else {
      assert(false && "CppKeywordCheck did not receive a valid Expr");
    }
  } else {
    StartLoc = ND->getLocation();
  }
  SourceLocation EndLoc =
      Lexer::getLocForEndOfToken(StartLoc, 1, SM, Ctx.getLangOpts());

  std::string Name = ND->getNameAsString();
  std::string RepName = "_" + Name;
  SourceRange Range(StartLoc, EndLoc);

  {
    const unsigned ID = DE.getCustomDiagID(DiagnosticsEngine::Warning,
                                           "'%0' conflicts with C++ keyword");
    auto DiagBuilder = DE.Report(StartLoc, ID);
    DiagBuilder.AddString(Name);
    auto Fix = FixItHint::CreateReplacement(Range, RepName);
    DiagBuilder.AddFixItHint(Fix);
  }
  if (Range.isInvalid()) {
    const unsigned ID =
        DE.getCustomDiagID(DiagnosticsEngine::Note, "use '%0' instead");
    auto DiagBuilder = DE.Report(SM.getSpellingLoc(StartLoc), ID);
    DiagBuilder.AddString(RepName);
  }
}

} // end namespace c2cpp
} // end namespace covert_tools
