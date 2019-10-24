//===---- TypePrinter.h - Pretty-print covert types as LLVM FixIt hints ---===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __CPP2COVERT_TYPE_PRINTER_H__
#define __CPP2COVERT_TYPE_PRINTER_H__

#include "clang/AST/Decl.h"
#include "clang/AST/PrettyPrinter.h"
#include "clang/AST/Stmt.h"

namespace covert_tools {
namespace cpp2covert {

/// \brief Pretty-prints Covert C++ types.
///
/// \details The `Replace*()` methods accept an AST node (e.g. `VarDecl`) and
/// a new `QualType` to be applied to that AST node. These methods perform the
/// necessary textual transformation, and return a list of FixIts which describe
/// the transformation, if the transformation is possible. For instance, a
/// transformation involving a macro expansion may not be possible.
class TypePrinter {
  clang::PrintingPolicy Policy;
  llvm::ArrayRef<std::string> Patterns;

  std::string &AdjustQualifiers(std::string &str) const;

public:
  using FixIts = std::vector<clang::FixItHint>;

  TypePrinter(clang::PrintingPolicy Policy,
              llvm::ArrayRef<std::string> QualifierRemovalPatterns);

  /// \brief Prints \p QT according to the given \c TypePrinterPolicy.
  std::string PrintType(clang::QualType QT) const;

  llvm::Optional<FixIts> ReplaceTypeLoc(const clang::ASTContext &Ctx,
                                        clang::TypeLoc Loc,
                                        clang::QualType QT) const;
  llvm::Optional<FixIts>
  ReplaceDeclStmt(const clang::ASTContext &Ctx, const clang::DeclStmt *DS,
                  llvm::ArrayRef<clang::QualType> QTs) const;
  llvm::Optional<FixIts> ReplaceVarDecl(const clang::ASTContext &Ctx,
                                        const clang::VarDecl *VD,
                                        clang::QualType QT) const;
  llvm::Optional<FixIts> ReplaceFieldDecl(const clang::ASTContext &Ctx,
                                          const clang::FieldDecl *FD,
                                          clang::QualType QT) const;
  llvm::Optional<FixIts> ReplaceFunctionReturn(const clang::ASTContext &Ctx,
                                               const clang::FunctionDecl *FD,
                                               clang::QualType QT) const;
};

} // end namespace cpp2covert
} // end namespace covert_tools

#endif
