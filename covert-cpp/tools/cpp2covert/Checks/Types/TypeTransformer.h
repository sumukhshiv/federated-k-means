//===---- TypeTransformer.h - Transforms primitive types into SE types ----===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __CPP2COVERT_TYPE_TRANSFORMER_H__
#define __CPP2COVERT_TYPE_TRANSFORMER_H__

#include "clang/AST/Decl.h"
#include "clang/AST/DeclTemplate.h"

namespace covert_tools {
namespace cpp2covert {

/// \brief Performs transformations on types, transforming non-SE types into SE
/// types.
class TypeTransformer {
  clang::ClassTemplateDecl *CovertDecl;
  clang::TypeAliasTemplateDecl *SEDecl;
  const clang::EnumDecl *SLabelDecl;
  const clang::EnumConstantDecl *SLabelLowDecl;
  const clang::EnumConstantDecl *SLabelHighDecl;

public:
  explicit TypeTransformer(const clang::TranslationUnitDecl *TUD);

  /// \brief Transforms a non-SE type into an SE type
  ///
  /// \param Ctx In the creation of a new SE type, \c Transform() literally adds
  /// a new specialization of SE to the AST context
  /// \param QT The non-SE type to transform
  /// \param IsSecret If true, set the deepest security label to `H`
  /// \return The transformed type, with the same cv qualifiers as \p QT, and at
  /// the same depths.
  clang::QualType Transform(clang::ASTContext &Ctx, clang::QualType QT,
                            bool IsSecret = false) const;
};

} // end namespace cpp2covert
} // end namespace covert_tools

#endif
