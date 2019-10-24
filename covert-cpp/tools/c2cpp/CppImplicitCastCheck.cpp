//===--- CppImplicitCastCheck.cpp - refactors implicit casts from enums ---===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "CppImplicitCastCheck.h"
#include "clang/Lex/Lexer.h"

using namespace clang;
using namespace clang::ast_matchers;

namespace covert_tools {
namespace c2cpp {

ICheck::MatcherArrayT CppImplicitCastCheck::getMatchers() const {
  static const ICheck::MatcherT Matchers[] = {
      implicitCastExpr(
          allOf(hasSourceExpression(expr().bind("SourceExpr")),
                anyOf(
                    // Named Enum
                    allOf(hasType(hasCanonicalType(enumType(
                              hasDeclaration(namedDecl().bind("EnumDecl"))))),
                          unless(hasType(typedefType()))),
                    // typedef'd Anonymous Enum
                    allOf(hasType(hasCanonicalType(enumType())),
                          hasType(typedefType(
                              hasDeclaration(namedDecl().bind("EnumDecl"))))),
                    allOf(hasSourceExpression(expr(
                              hasType(hasCanonicalType(pointsTo(voidType()))))),
                          unless(hasType(
                              hasCanonicalType(pointsTo(voidType()))))))))
          .bind("CastExpr")};
  return Matchers;
}

void CppImplicitCastCheck::run(const MatchFinder::MatchResult &Result) {
  auto ICE = Result.Nodes.getNodeAs<ImplicitCastExpr>("CastExpr");
  assert(ICE);
  auto E = Result.Nodes.getNodeAs<Expr>("SourceExpr");
  assert(E);
  if (auto ND = Result.Nodes.getNodeAs<NamedDecl>("decl")) {
    // ignore anonymous types
    if (ND->getName().empty())
      return;
  }

  ASTContext &Ctx = *Result.Context;
  SourceManager &SM = *Result.SourceManager;
  DiagnosticsEngine &DE = Ctx.getDiagnostics();

  SourceLocation BeginLoc = ICE->getBeginLoc();
  SourceLocation EndLoc =
      Lexer::getLocForEndOfToken(ICE->getEndLoc(), 0, SM, Ctx.getLangOpts());
  std::string explicitCast, endCast;
  explicitCast = "static_cast<" + ICE->getType().getAsString() + ">(";
  endCast = ")";

  const unsigned ID =
      DE.getCustomDiagID(DiagnosticsEngine::Warning,
                         "Implicit cast from %0 to %1 is not allowed in C++");
  auto DiagBuilder = DE.Report(BeginLoc, ID);
  DiagBuilder << E->getType();
  DiagBuilder << ICE->getType();
  DiagBuilder << FixItHint::CreateInsertion(BeginLoc, std::move(explicitCast));
  DiagBuilder << FixItHint::CreateInsertion(EndLoc, std::move(endCast));
}

} // end namespace c2cpp
} // end namespace covert_tools
