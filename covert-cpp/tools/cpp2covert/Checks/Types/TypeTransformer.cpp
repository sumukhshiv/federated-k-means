//===--- TypeTransformer.cpp - Transforms primitive types into SE types ---===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "TypeTransformer.h"

using namespace clang;

namespace covert_tools {
namespace cpp2covert {

/// \brief Finds all namespace definitions of the given name.
///
/// Only finds namespaces defined in the global scope. So nested namespaces
/// cannot be found using this function.
static std::vector<clang::NamespaceDecl *>
getNamespacesByName(const DeclContext *DC, llvm::StringRef Name) {
  std::vector<clang::NamespaceDecl *> NSs;
  for (auto &d : DC->decls()) {
    if (auto *tmp = dyn_cast<NamespaceDecl>(d)) {
      if (tmp->getName() == Name) {
        NSs.push_back(tmp);
      }
    }
  }
  return NSs;
}

/// Searches \p TUD for the relevant Covert C++ type/enum definitions.
TypeTransformer::TypeTransformer(const TranslationUnitDecl *TUD)
    : CovertDecl(nullptr), SEDecl(nullptr), SLabelDecl(nullptr),
      SLabelLowDecl(nullptr), SLabelHighDecl(nullptr) {
  std::vector<NamespaceDecl *> CovertNSs, SE_NSs;

  CovertNSs = getNamespacesByName(TUD, "covert");
  if (CovertNSs.empty()) {
    llvm::errs() << "Error: could not find 'covert' namespace\n";
    exit(1);
  }

  for (NamespaceDecl *CovertNS : CovertNSs) {
    for (auto NS : getNamespacesByName(CovertNS, "se")) {
      SE_NSs.push_back(NS);
    }
  }
  if (SE_NSs.empty()) {
    llvm::errs() << "Error: could not find 'covert::se' namespace\n";
    exit(1);
  }

  // Find the SLabel enum decl and SE decl
  for (auto &ns : SE_NSs) {
    for (auto &d : ns->decls()) {
      if (const auto *SLabel_tmp = dyn_cast<EnumDecl>(d)) {
        if (SLabel_tmp->getName() == "SLabel") {
          SLabelDecl = SLabel_tmp;
        }
      }
      if (auto *SE_tmp = dyn_cast<TypeAliasTemplateDecl>(d)) {
        if (SE_tmp->getName() == "SE") {
          SEDecl = SE_tmp;
        }
      }
      if (SLabelDecl && SEDecl) {
        break;
      }
    }
    if (!SLabelDecl) {
      llvm::errs() << "Error: could not find the 'SLabel' declaration\n";
      exit(1);
    }
    if (!SEDecl) {
      llvm::errs() << "Error: could not find the 'SE' declaration\n";
      exit(1);
    }
  }

  // Get the L and H constants
  for (const auto &d : SLabelDecl->enumerators()) {
    if (d->getName() == "L")
      SLabelLowDecl = d;
    else if (d->getName() == "H")
      SLabelHighDecl = d;
  }
  if (!SLabelLowDecl || !SLabelHighDecl) {
    llvm::errs() << "Error: could not find the 'SLabel' declarations\n";
    exit(1);
  }

  // Get the Covert template class
  for (auto &ns : CovertNSs) {
    for (auto &d : ns->decls()) {
      if (auto *Covert_tmp = dyn_cast<ClassTemplateDecl>(d)) {
        if (Covert_tmp->getName() == "Covert") {
          if (!Covert_tmp->isThisDeclarationADefinition()) {
            CovertDecl = Covert_tmp;
            break;
          }
        }
      }
    }
  }
  if (!CovertDecl) {
    llvm::errs() << "Error: could not find the 'Covert' declaration\n";
    exit(1);
  }
}

static unsigned TypeDepth_aux(unsigned Depth, const Type *T) {
  if (T->isArithmeticType() || T->isEnumeralType()) {
    return Depth + 1;
  } else if (T->isPointerType()) {
    return TypeDepth_aux(Depth + 1, T->getPointeeType().getTypePtr());
  } else if (T->isLValueReferenceType()) {
    return TypeDepth_aux(Depth, T->getPointeeType().getTypePtr());
  } else if (T->isArrayType()) {
    return TypeDepth_aux(Depth, T->getArrayElementTypeNoTypeQual());
  } else {
    return Depth;
  }
}

/// \brief Analagous to the covert::type_depth metafunction.
static unsigned TypeDepth(const Type *T) { return TypeDepth_aux(0, T); }

QualType TypeTransformer::Transform(ASTContext &Ctx, QualType QT,
                                    bool IsSecret) const {
  QualType InnerType = QT.getCanonicalType().hasQualifiers()
                           ? QT.getCanonicalType().getUnqualifiedType()
                           : QT;

  llvm::SmallVector<TemplateArgument, 5> Args;
  Args.push_back(TemplateArgument(QualType(SLabelDecl->getTypeForDecl(), 0)));
  Args.push_back(TemplateArgument(InnerType));
  for (unsigned i = TypeDepth(InnerType.getTypePtr()); i > 0; --i) {
    auto Label = i == 1 && IsSecret ? SLabelHighDecl : SLabelLowDecl;
    Args.push_back(TemplateArgument(
        Ctx, Label->getInitVal(),
        SLabelDecl->getTypeForDecl()->getCanonicalTypeUnqualified()));
  }
  llvm::ArrayRef<TemplateArgument> CovertArgs = Args;

  // First search the AST for an equivalent existing specialization
  void *InsertPos;
  ClassTemplateSpecializationDecl *TD =
      CovertDecl->findSpecialization(Args, InsertPos);
  if (!TD) {
    // If we couldn't find an existing specialization, create one and add it to
    // the AST
    TD = ClassTemplateSpecializationDecl::Create(
        Ctx, TagTypeKind::TTK_Struct, CovertDecl->getDeclContext(),
        CovertDecl->getBeginLoc(), CovertDecl->getLocation(), CovertDecl,
        CovertArgs, nullptr);
    CovertDecl->AddSpecialization(TD, InsertPos);
  }

  QualType CovertType = QualType(TD->getTypeForDecl(), 0);

  llvm::ArrayRef<TemplateArgument> SEArgs(Args.begin() + 1, Args.size() - 1);
  QualType SEType = Ctx.getTemplateSpecializationType(TemplateName(SEDecl),
                                                      SEArgs, CovertType);
  return QualType(SEType.getTypePtr(), QT.getCVRQualifiers());

  // Don't forget to reattach the CV qualifiers!
  return QualType(TD->getTypeForDecl(), QT.getCVRQualifiers());
}

} // end namespace cpp2covert
} // end namespace covert_tools
