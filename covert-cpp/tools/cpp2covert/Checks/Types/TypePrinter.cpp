//===--- TypePrinter.cpp - Pretty-print covert types as LLVM FixIt hints --===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "TypePrinter.h"
#include "clang/AST/ASTContext.h"
#include "clang/Lex/Lexer.h"

using namespace clang;

namespace covert_tools {
namespace cpp2covert {

/// \brief Returns `true` if \p Loc contains any CV qualifiers.
static bool hasAnyQualifiers(TypeLoc Loc) {
  if (!Loc)
    return false;
  return Loc.getType().hasLocalQualifiers() ||
         hasAnyQualifiers(Loc.getNextTypeLoc());
}

/// \brief Obtain the full source range at character granularity, rather than
/// token granularity.
static CharSourceRange GetFullSourceRange(const ASTContext &Ctx,
                                          SourceRange Range) {
  SourceLocation BeginLoc = Range.getBegin();
  SourceLocation EndLoc = Lexer::getLocForEndOfToken(
      Range.getEnd(), 0, Ctx.getSourceManager(), Ctx.getLangOpts());
  return CharSourceRange::getCharRange(BeginLoc, EndLoc);
}

/// \brief Helper function.
///
/// Determines whether rewriting the TypeLoc \p Loc in \p DD will require an
/// additional space after the rewritten TypeLoc. For example, rewriting
/// \code
/// SECRET int *x;
/// \endcode
/// would require an extra space:
/// \code
/// SECRET SE<int *, L, H> x;
///                       ^
///                       Here
/// \endcode
static bool RequiresExtraSpace(const ASTContext &Ctx, const DeclaratorDecl *DD,
                               TypeLoc Loc) {
  if (!DD->getName().empty()) {
    SourceLocation TypeEndLoc = Lexer::getLocForEndOfToken(
        Loc.getEndLoc(), 0, Ctx.getSourceManager(), Ctx.getLangOpts());
    SourceLocation NameBeginLoc = DD->getLocation();
    if (TypeEndLoc == NameBeginLoc && Loc.getTypePtr()->isPointerType()) {
      return true;
    }
  }
  return false;
}

TypePrinter::TypePrinter(PrintingPolicy Policy,
                         llvm::ArrayRef<std::string> QualifierRemovalPatterns)
    : Policy(Policy), Patterns(QualifierRemovalPatterns) {}

/// \details Adds/removes namespace/class/enum qualifiers depending on the
/// #Policy and #QualifierRemovalPatterns.
std::string &TypePrinter::AdjustQualifiers(std::string &str) const {
  for (const auto &pattern : Patterns) {
    std::string::size_type i = str.find(pattern);
    while (i != std::string::npos) {
      str.erase(i, pattern.length());
      i = str.find(pattern, i);
    }
  }
  return str;
}

std::string TypePrinter::PrintType(clang::QualType QT) const {
  std::string ret = QT.getAsString(Policy);
  return AdjustQualifiers(ret);
}

llvm::Optional<TypePrinter::FixIts>
TypePrinter::ReplaceTypeLoc(const ASTContext &Ctx, TypeLoc Loc,
                            QualType QT) const {
  if (hasAnyQualifiers(Loc)) {
    return None;
  }

  FixIts Fixes;
  CharSourceRange Range;
  std::string TypeStr;

  if (auto ArrayLoc = Loc.getAs<ArrayTypeLoc>()) {
    Range = GetFullSourceRange(Ctx, ArrayLoc.getElementLoc().getSourceRange());
    if (!QT.getTypePtr()->isArrayType()) {
      CharSourceRange ArraySizeRange =
          GetFullSourceRange(Ctx, SourceRange(ArrayLoc.getLBracketLoc(),
                                              ArrayLoc.getRBracketLoc()));
      if (ArraySizeRange.isInvalid()) {
        return None;
      }
      Fixes.push_back(FixItHint::CreateRemoval(ArraySizeRange));
      TypeStr = PrintType(QT);
    } else {
      TypeStr =
          PrintType(QualType(QT.getTypePtr()->getArrayElementTypeNoTypeQual(),
                             QT.getCVRQualifiers()));
    }
  } else {
    Range = GetFullSourceRange(Ctx, Loc.getSourceRange());
    TypeStr = PrintType(QT);
  }

  if (Range.isInvalid()) {
    return None;
  }

  Fixes.push_back(FixItHint::CreateReplacement(Range, TypeStr));
  return Fixes;
}

llvm::Optional<TypePrinter::FixIts>
TypePrinter::ReplaceDeclStmt(const ASTContext &Ctx, const DeclStmt *DS,
                             llvm::ArrayRef<QualType> QTs) const {
  assert((DS->isSingleDecl() && QTs.size() == 1) ||
         (DS->getDeclGroup().getDeclGroup().size() == QTs.size()));
  std::string out;
  llvm::raw_string_ostream os(out);

  auto Range = GetFullSourceRange(Ctx, DS->getSourceRange());
  if (Range.isInvalid()) {
    return None;
  }

  // Easy case: a singleton DeclStmt
  if (DS->isSingleDecl()) {
    auto VD = dyn_cast<VarDecl>(DS->getSingleDecl());
    return ReplaceVarDecl(Ctx, VD, QTs[0]);
  }

  // Otherwise, find out whether all the Decls have the same type
  bool all_same_type = true;
  QualType FirstQT = QTs[0];
  for (auto I = QTs.begin() + 1; I != QTs.end(); ++I) {
    if (!Ctx.hasSameType(*I, FirstQT)) {
      all_same_type = false;
      break;
    }
  }

  auto FirstDecl = dyn_cast<VarDecl>(*DS->decl_begin());
  TypeLoc FirstLoc = FirstDecl->getTypeSourceInfo()->getTypeLoc();
  if (all_same_type && !hasAnyQualifiers(FirstLoc)) {
    // If all Decl's are the same type, only print the type once, at the
    // beginning
    auto Fixes = ReplaceVarDecl(Ctx, FirstDecl, FirstQT);
    if (!Fixes)
      return None;
    for (auto I = DS->decl_begin() + 1, E = DS->decl_end(); I != E; ++I) {
      auto DD = dyn_cast<DeclaratorDecl>(*I);
      auto PLoc = DD->getTypeSourceInfo()->getTypeLoc().getAs<PointerTypeLoc>();
      while (!PLoc.isNull()) {
        // If we're replacing non-singleton pointer DeclStmt, remove the extra
        // pointer '*' characters from each Decl
        Fixes->push_back(FixItHint::CreateRemoval(PLoc.getStarLoc()));
        PLoc = PLoc.getNextTypeLoc().getAs<PointerTypeLoc>();
      }
    }
    return Fixes;
  } else { // Otherwise, replace the entire DeclStmt
    std::string DeclStr;
    llvm::raw_string_ostream os(DeclStr);
    auto DeclI = DS->decl_begin();
    auto TypeI = QTs.begin();
    do {
      auto DD = dyn_cast<DeclaratorDecl>(*DeclI);
      QualType OldQT = DD->getType();
      DD->getTypeSourceInfo()->overrideType(*TypeI);
      DD->print(os, Policy, 0, true);
      DD->getTypeSourceInfo()->overrideType(OldQT);
      os << ';';
      if (DeclI + 1 != DS->decl_end())
        os << ' ';
    } while (++DeclI != DS->decl_end() && ++TypeI != QTs.end());
    AdjustQualifiers(os.str());
    return {{FixItHint::CreateReplacement(Range, os.str())}};
  }
}

llvm::Optional<TypePrinter::FixIts>
TypePrinter::ReplaceVarDecl(const ASTContext &Ctx, const VarDecl *VD,
                            QualType QT) const {
  TypeLoc Loc = VD->getTypeSourceInfo()->getTypeLoc();
  if (!hasAnyQualifiers(Loc)) {
    // If Loc doesn't have any qualifiers, we can get away with only replacing
    // the type
    auto Fixes = ReplaceTypeLoc(Ctx, Loc, QT);
    if (Fixes && RequiresExtraSpace(Ctx, VD, Loc)) {
      assert(Fixes->size() == 1);
      Fixes->front().CodeToInsert += ' ';
    }
    return Fixes;
  }

  // Otherwise, we probably need to replace the whole VarDecl, minus the
  // initializer (if one exists)
  Expr *Init = nullptr;
  if (VD->hasInit()) {
    VarDecl *_VD = const_cast<VarDecl *>(VD);
    Init = _VD->getInit();
    _VD->setInit(nullptr);
  }

  CharSourceRange Range = GetFullSourceRange(Ctx, VD->getSourceRange());
  if (Range.isInvalid()) {
    return None;
  }
  QualType OldQT = VD->getType();
  std::string TypeStr;
  llvm::raw_string_ostream os(TypeStr);

  // Temporarily replace the type (we don't want to "damage" the AST!)
  VD->getTypeSourceInfo()->overrideType(QT);
  VD->print(os, Policy, 0, true);
  VD->getTypeSourceInfo()->overrideType(OldQT);

  // If we had removed the initializer, don't forget to reattach it!
  if (Init) {
    VarDecl *_VD = const_cast<VarDecl *>(VD);
    _VD->setInit(Init);
  }

  AdjustQualifiers(os.str());
  return {{FixItHint::CreateReplacement(Range, os.str())}};
}

llvm::Optional<TypePrinter::FixIts>
TypePrinter::ReplaceFieldDecl(const ASTContext &Ctx, const FieldDecl *FD,
                              QualType QT) const {
  TypeLoc Loc = FD->getTypeSourceInfo()->getTypeLoc();
  if (!hasAnyQualifiers(Loc)) {
    // If Loc doesn't have any qualifiers, we can get away with only replacing
    // the type
    auto Fixes = ReplaceTypeLoc(Ctx, Loc, QT);
    if (Fixes && RequiresExtraSpace(Ctx, FD, Loc)) {
      assert(Fixes->size() == 1);
      Fixes->front().CodeToInsert += ' ';
    }
    return Fixes;
  }

  FieldDecl *_FD = const_cast<FieldDecl *>(FD);
  CharSourceRange Range = GetFullSourceRange(Ctx, FD->getSourceRange());
  if (Range.isInvalid()) {
    return None;
  }
  QualType OldQT = FD->getType();
  std::string TypeStr;
  llvm::raw_string_ostream os(TypeStr);

  // Temporarily replace the type (we don't want to "damage" the AST!)
  _FD->setType(QT);
  FD->print(os, Policy, 0, true);
  _FD->setType(OldQT);

  AdjustQualifiers(os.str());
  return {{FixItHint::CreateReplacement(Range, os.str())}};
}

/// \details **NOTE:** `ReplaceFunctionReturn` cannot replace return types with
/// any CV qualifiers, because this can be a total mess for functions. For
/// instance,
/// \code
/// const inline static int *foo();
/// \endcode
/// is a valid declaration in C++. Since non-type keywords can be interspersed
/// with the return type, this means we would have to replace the entire
/// function definition. This becomes even more agonizing when we consider
/// trailing return types in C++11...
llvm::Optional<TypePrinter::FixIts>
TypePrinter::ReplaceFunctionReturn(const clang::ASTContext &Ctx,
                                   const clang::FunctionDecl *FD,
                                   clang::QualType QT) const {
  TypeLoc ReturnLoc = FD->getTypeSourceInfo()
                          ->getTypeLoc()
                          .castAs<FunctionTypeLoc>()
                          .getReturnLoc();
  auto Fixes = ReplaceTypeLoc(Ctx, ReturnLoc, QT);
  if (Fixes && RequiresExtraSpace(Ctx, FD, ReturnLoc)) {
    assert(Fixes->size() == 1);
    Fixes->front().CodeToInsert += ' ';
  }
  return Fixes;
}

} // end namespace cpp2covert
} // end namespace covert_tools
