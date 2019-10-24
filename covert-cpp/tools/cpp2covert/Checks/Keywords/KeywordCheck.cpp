//===----- KeywordCheck.cpp - Check for IDs that clash with Covert C++ ----===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "KeywordCheck.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/StringSet.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::ast_matchers::internal;

namespace covert_tools {
namespace cpp2covert {

/// \brief Matches any NamedDecl whose identifier conflicts with a Covert C++
/// keyword.
///
/// Given:
/// \code
/// int L = 0;
/// int K = 1;
/// class SE {
///   ...
/// };
/// \endcode
/// matches `L` and `SE`.
AST_MATCHER(NamedDecl, isCovertKeyword) {
  static const llvm::StringSet<> Keywords = {"SE",
                                             "L",
                                             "H",
                                             "SLabel",
                                             "se_to_primitive",
                                             "se_label_cast",
                                             "se_static_cast",
                                             "se_dynamic_cast",
                                             "se_const_cast",
                                             "se_reinterpret_cast"};

  if (const IdentifierInfo *ID = Node.getIdentifier()) {
    return Keywords.find(ID->getName()) != Keywords.end();
  }

  return false;
}

/// \brief Matches any Decl in the given namespace.
AST_MATCHER_P(Decl, declaredInNamespace, std::string, NameSpace) {
  for (const DeclContext *D = Node.getDeclContext(); D; D = D->getParent()) {
    if (const NamespaceDecl *ND = dyn_cast<NamespaceDecl>(D)) {
      const IdentifierInfo *Info = ND->getIdentifier();
      if (Info && Info->getName() == NameSpace)
        return true;
    }
  }

  return false;
}

void KeywordCheck::run(const MatchResultT &Result) {
  auto ND = Result.Nodes.getNodeAs<NamedDecl>("KeywordDecl");

  SourceManager &SM = *Result.SourceManager;
  ASTContext &Ctx = *Result.Context;

  DiagnosticsEngine &DE = Ctx.getDiagnostics();
  const unsigned ID =
      DE.getCustomDiagID(DiagnosticsEngine::Warning,
                         "Name '%0' conflicts with Covert C++ keyword");

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
      assert(false && "KeywordCheck did not receive a valid Expr");
    }
  } else {
    StartLoc = ND->getLocation();
  }
  SourceLocation EndLoc =
      Lexer::getLocForEndOfToken(StartLoc, 1, SM, Ctx.getLangOpts());

  std::string Name = ND->getNameAsString();
  std::string RepName = "_" + Name;
  auto DiagBuilder = DE.Report(StartLoc, ID);
  DiagBuilder.AddString(Name);
  const auto Fix =
      FixItHint::CreateReplacement(SourceRange(StartLoc, EndLoc), RepName);
  DiagBuilder.AddFixItHint(Fix);
}

ICheck::MatcherArrayT KeywordCheck::getMatchers() const {
  static const DeclarationMatcher KeywordDeclMatcher =
      namedDecl(allOf(isCovertKeyword(),
                      unless(declaredInNamespace("se")),
                      unless(isImplicit())))
          .bind("KeywordDecl");

  static const ICheck::MatcherT Matchers[] = {
      KeywordDeclMatcher,
      loc(qualType(hasDeclaration(KeywordDeclMatcher))).bind("type"),
      expr(anyOf(declRefExpr(hasDeclaration(KeywordDeclMatcher)).bind("expr"),
                 memberExpr(hasDeclaration(KeywordDeclMatcher)).bind("expr")))};

  return Matchers;
}

} // end namespace cpp2covert
} // end namespace covert_tools
