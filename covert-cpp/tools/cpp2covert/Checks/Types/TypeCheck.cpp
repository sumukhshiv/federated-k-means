//===-- TypeCheck.cpp - Find primitive types and refactor to covert types -===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "TypeCheck.h"
#include "TypePrinter.h"
#include "TypeTransformer.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::ast_matchers::internal;

namespace covert_tools {
namespace cpp2covert {

CovertTypeCheckPolicy::CovertTypeCheckPolicy()
    : clang::PrintingPolicy(clang::LangOptions()) {
  this->adjustForCPlusPlus();
}

/// \brief Traverse a (possibly cv-qualified) type, applying \p f at each level.
///
/// If the type is
/// - an array type, then the element type is traversed
/// - an lvalue reference type, then the referenced type is traversed
/// - a pointer type, then the pointee type is traversed
///
/// For example, calling `TraversePrimitiveTypeWrapper(f, T)` where `T` is the
/// type `const int *&` will produce the call stack:
/// \verbatim
/// Traverse(f, const int *&)
/// Traverse(f, const int *)
/// Traverse(f, const int)
/// \endverbatim
/// and apply `f` three times:
/// \verbatim
/// f(const int *&)
/// f(const int *)
/// f(const int)
/// \endverbatim
static void TraversePrimitiveTypeWrapper(std::function<void(clang::QualType)> f,
                                         clang::QualType QT) {
  f(QT);
  const Type *T = QT.getTypePtr();
  if (auto InnerT = T->getAsArrayTypeUnsafe()) {
    TraversePrimitiveTypeWrapper(f, InnerT->getElementType());
  } else if (auto InnerT = T->getAs<LValueReferenceType>()) {
    TraversePrimitiveTypeWrapper(f, InnerT->getPointeeType());
  } else if (auto InnerT = T->getAs<PointerType>()) {
    TraversePrimitiveTypeWrapper(f, InnerT->getPointeeType());
  }
}

/// Returns \c true if \p T contains a template type parameter, and thus depends
/// on a template instantiation.
static bool hasTemplateTypeParmType(const Type *T) {
  bool ret = false;
  TraversePrimitiveTypeWrapper(
      [&ret](QualType T) { ret |= T->isTemplateTypeParmType(); },
      QualType(T, 0));
  return ret;
}

/// Returns \c true if \p T contains a template type parameter substitution.
static bool hasSubstTemplateTypeParmType(const Type *T) {
  bool ret = false;
  TraversePrimitiveTypeWrapper(
      [&ret](QualType T) {
        ret = ret || (bool)T->getAs<SubstTemplateTypeParmType>();
      },
      QualType(T, 0));
  return ret;
}

/// Returns \c true if \p T is primitive, according to the Covert C++ standard.
static bool IsPrimitiveType(const Type *T) {
  return T->isArithmeticType() ||
         (T->isPointerType() && !T->isFunctionPointerType()) ||
         T->isEnumeralType();
}

/// \brief Returns \c true if \p T wraps a primitive type.
///
/// For example, `int &`, `int *[4]`, etc.
static bool IsPrimitiveTypeWrapper(const Type *T) {
  return IsPrimitiveType(T) ||
         (T->isArrayType() &&
          IsPrimitiveType(T->getArrayElementTypeNoTypeQual())) ||
         (T->isLValueReferenceType() &&
          IsPrimitiveType(T->getPointeeType().getTypePtr()));
}

/// Returns \c true if \p T is a primitive type wrapper, and does not depend on
/// a template type parameter.
static bool IsNonDependentPrimitiveTypeWrapper(const Type *T) {
  return IsPrimitiveTypeWrapper(T) && !hasTemplateTypeParmType(T);
}

///////////////////////////////////////
// Custom AST Matchers
///////////////////////////////////////

/// \brief Matches a type that is not dependent on a template type parameter.
///
/// Given:
/// \code
/// template <typename T>
/// struct C {
///   const T *ptr;
///   const void *vptr;
/// };
/// \endcode
/// Matches `const T *` but not `const void *`.
AST_MATCHER(Type, nonDependentPrimitiveTypeWrapper) {
  return IsNonDependentPrimitiveTypeWrapper(&Node);
}

/// \brief Matches a function declaration that specializes a function template.
AST_MATCHER(FunctionDecl, isFunctionTemplateSpecialization) {
  return Node.isFunctionTemplateSpecialization();
}

/// \brief Matches a declaration which was declared in the given namespace at
/// any level.
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

/// \brief Returns \c true if \p D has the "secret" annotation.
///
/// Identifies declarations made with the "secret" annotation, e.g.
/// \code
/// __attribute__((annotate("secret"))) int *x;
/// \endcode
/// but works for non-GNU stye attributes as well.
static bool DeclIsSecret(const Decl *D) {
  if (auto AA = D->getAttr<AnnotateAttr>()) {
    if (AA->getAnnotation() == "secret") {
      return true;
    }
  }
  return false;
}

/// \brief The implementation class for CovertTypeCheck.
///
/// Note: This class is a little bit inelegant because MatchCallbacks are
/// supposed to be stateless, but TypeRewriterCallback is not.
class TypeRewriterCallback : public MatchFinder::MatchCallback {
  CovertTypeCheckPolicy Policy;
  std::unique_ptr<TypeTransformer> Transformer;
  TypePrinter Printer;

  /// Emit "use type [\p QT] instead" at \p SLoc
  void EmitTypeHelperDiagnostic(DiagnosticsEngine &DE, SourceLocation SLoc,
                                QualType QT) const {
    const unsigned ID =
        DE.getCustomDiagID(DiagnosticsEngine::Note, "use type '%0' instead");
    DiagnosticBuilder DB = DE.Report(SLoc, ID);
    DB << Printer.PrintType(QT);
  }

  /// For a diagnostic originating from a template specialization, emit the
  /// backtrace.
  void EmitTemplateBacktrace(DiagnosticsEngine &DE,
                             const NamedDecl *TemplateSpec) const {
    if (auto FD = dyn_cast<FunctionDecl>(TemplateSpec)) {
      assert(FD->isFunctionTemplateSpecialization());
      const unsigned ID = DE.getCustomDiagID(
          DiagnosticsEngine::Note,
          "in instantiation of function template %0 requested here");
      DiagnosticBuilder DB = DE.Report(FD->getPointOfInstantiation(), ID);
      DB << FD;
    } else if (auto CD =
                   dyn_cast<ClassTemplateSpecializationDecl>(TemplateSpec)) {
      const unsigned ID = DE.getCustomDiagID(
          DiagnosticsEngine::Note,
          "in instantiation of template class %0 requested here");
      DiagnosticBuilder DB = DE.Report(CD->getPointOfInstantiation(), ID);
      DB << CD->getTypeForDecl()->getCanonicalTypeUnqualified();
    } else {
      TemplateSpec->dump();
      assert(false && "Invalid template specialization!");
    }
  }

  /// Transform \p QT into an SE type.
  ///
  /// If \p IsSecret is \c true, set the backmost label to \c H.
  QualType Transform(ASTContext &Ctx, QualType QT, bool IsSecret) const {
    QualType CanonicalQT = QT.getCanonicalType();
    const Type *T = CanonicalQT.getTypePtr();
    if (auto ArrayT = T->getAsArrayTypeUnsafe()) {
      QualType EleQT = QualType(ArrayT->getElementType().getTypePtr(),
                                CanonicalQT.getCVRQualifiers());
      QualType NewEleQT = Transformer->Transform(Ctx, EleQT, IsSecret);
      if (auto ConstArrayT = dyn_cast<ConstantArrayType>(ArrayT)) {
        return Ctx.getConstantArrayType(
            NewEleQT, ConstArrayT->getSize(), ConstArrayT->getSizeModifier(),
            ConstArrayT->getIndexTypeCVRQualifiers());
      } else if (auto IncompleteArrayT =
                     dyn_cast<IncompleteArrayType>(ArrayT)) {
        return Ctx.getIncompleteArrayType(
            NewEleQT, IncompleteArrayT->getSizeModifier(),
            IncompleteArrayT->getIndexTypeCVRQualifiers());
      } else if (auto VariableArrayT = dyn_cast<VariableArrayType>(ArrayT)) {
        return Ctx.getVariableArrayType(
            NewEleQT, VariableArrayT->getSizeExpr(),
            VariableArrayT->getSizeModifier(),
            VariableArrayT->getIndexTypeCVRQualifiers(),
            VariableArrayT->getBracketsRange());
      } else if (auto DependentArrayT =
                     dyn_cast<DependentSizedArrayType>(ArrayT)) {
        return Ctx.getDependentSizedArrayType(
            NewEleQT, DependentArrayT->getSizeExpr(),
            DependentArrayT->getSizeModifier(),
            DependentArrayT->getIndexTypeCVRQualifiers(),
            DependentArrayT->getBracketsRange());
      }
    } else if (auto RefT = T->getAs<LValueReferenceType>()) {
      QualType NewPointeeQT =
          Transformer->Transform(Ctx, RefT->getPointeeType(), IsSecret);
      return Ctx.getLValueReferenceType(NewPointeeQT);
    }
    return Transformer->Transform(Ctx, QT, IsSecret);
  }

  /// Transform the type(s) in a \c DeclStmt into \c SE types.
  ///
  /// If a \p TemplateSpec is provided, emits a template backtrace.
  void RewriteDeclStmt(ASTContext &Ctx, const DeclStmt *DS,
                       const NamedDecl *TemplateSpec) const {
    DiagnosticsEngine &DE = Ctx.getDiagnostics();

    // Take care of the easy case where we only have one VarDecl
    if (DS->isSingleDecl()) {
      auto VD = dyn_cast<VarDecl>(DS->getSingleDecl());
      RewriteDeclaratorDecl(Ctx, VD, TemplateSpec);
      return;
    }

    // We have a sequence of VarDecls, generate the new types
    llvm::SmallVector<QualType, 4> TypesForDecls;
    llvm::SmallVector<QualType, 4> NewTypesForDecls;
    for (const auto &D : DS->decls()) {
      auto VD = dyn_cast<VarDecl>(D);
      assert(VD);
      bool IsSecret = DeclIsSecret(VD);
      QualType QT = VD->getType();
      TypesForDecls.push_back(QT);
      QualType NewQT;
      if (!IsSecret && Policy.RewriteSecretOnly) {
        NewQT = QT;
      } else {
        NewQT = IsNonDependentPrimitiveTypeWrapper(QT.getTypePtr())
                    ? Transform(Ctx, QT, IsSecret)
                    : QT;
      }
      NewTypesForDecls.push_back(NewQT);
    }

    llvm::Optional<TypePrinter::FixIts> Fixes =
        Printer.ReplaceDeclStmt(Ctx, DS, NewTypesForDecls);

    std::size_t i = 0;
    for (const auto &D : DS->decls()) {
      QualType QT = TypesForDecls[i];
      if (TemplateSpec && !hasSubstTemplateTypeParmType(QT.getTypePtr())) {
        continue;
      }
      QualType NewQT = NewTypesForDecls[i];
      ++i;
      auto VD = dyn_cast<VarDecl>(D);
      if (QT != NewQT) {
        {
          const unsigned ID = DE.getCustomDiagID(
              DiagnosticsEngine::Warning, "%0 declared with primitive type %1");
          DiagnosticBuilder DB = DE.Report(VD->getLocation(), ID);
          DB << VD << QT;
        }

        if (TemplateSpec) {
          EmitTemplateBacktrace(DE, TemplateSpec);
        }
        if (!Fixes) {
          EmitTypeHelperDiagnostic(
              DE, DE.getSourceManager().getSpellingLoc(VD->getLocation()),
              NewQT);
        }
      }
    }
    if (Fixes && !TemplateSpec) {
      const unsigned ID =
          DE.getCustomDiagID(DiagnosticsEngine::Note, "suggested rewrite:");
      DiagnosticBuilder DB = DE.Report(DS->getBeginLoc(), ID);
      DB << *Fixes;
    }
  }

  /// Transform the type in a \c DeclaratorDecl into \c SE types.
  ///
  /// If a \p TemplateSpec is provided, emits a template backtrace.
  void RewriteDeclaratorDecl(ASTContext &Ctx, const DeclaratorDecl *DD,
                             const NamedDecl *TemplateSpec) const {
    DiagnosticsEngine &DE = Ctx.getDiagnostics();

    bool IsSecret = DeclIsSecret(DD);
    if (!IsSecret && Policy.RewriteSecretOnly) {
      return;
    }
    llvm::Optional<TypePrinter::FixIts> Fixes = None;
    QualType QT, NewQT;
    if (auto FuncD = dyn_cast<FunctionDecl>(DD)) {
      QT = FuncD->getReturnType();
      NewQT = Transform(Ctx, QT, IsSecret);
    } else {
      QT = DD->getType();
      NewQT = Transform(Ctx, QT, IsSecret);
    }

    if (!TemplateSpec) {
      if (auto FuncD = dyn_cast<FunctionDecl>(DD)) {
        Fixes = Printer.ReplaceFunctionReturn(Ctx, FuncD, NewQT);
      } else if (auto VD = dyn_cast<VarDecl>(DD)) {
        Fixes = Printer.ReplaceVarDecl(Ctx, VD, NewQT);
      } else if (auto FieldD = dyn_cast<FieldDecl>(DD)) {
        Fixes = Printer.ReplaceFieldDecl(Ctx, FieldD, NewQT);
      }
    } else {
      if (!hasSubstTemplateTypeParmType(QT.getTypePtr())) {
        return;
      }
    }

    if (!DD->getName().empty()) {
      const unsigned ID = DE.getCustomDiagID(
          DiagnosticsEngine::Warning, "%0 declared with primitive type %1");
      auto DiagBuilder = DE.Report(DD->getLocation(), ID);
      DiagBuilder << DD << QT;
      if (Fixes) {
        DiagBuilder << *Fixes;
      }
    } else {
      const unsigned ID =
          DE.getCustomDiagID(DiagnosticsEngine::Warning,
                             "Parameter declared with primitive type %0");
      auto DiagBuilder = DE.Report(DD->getLocation(), ID);
      DiagBuilder << QT;
      if (Fixes) {
        DiagBuilder << *Fixes;
      }
    }

    if (TemplateSpec) {
      EmitTemplateBacktrace(DE, TemplateSpec);
    }
    if (!Fixes) {
      EmitTypeHelperDiagnostic(
          DE, DE.getSourceManager().getSpellingLoc(DD->getLocation()), NewQT);
    }
  }

public:
  using MatchResult = MatchFinder::MatchResult;

  TypeRewriterCallback(CovertTypeCheckPolicy Policy,
                       llvm::ArrayRef<std::string> QualifierRemovalPatterns)
      : Policy(Policy), Printer(Policy, QualifierRemovalPatterns) {}

  /// \details resets Transformer
  void onStartOfTranslationUnit() override { Transformer.reset(nullptr); }

  void run(const MatchResult &Result) override {
    ASTContext &Ctx = *Result.Context;
    if (!Transformer) {
      Transformer.reset(new TypeTransformer(Ctx.getTranslationUnitDecl()));
    }
    auto TemplateSpec =
        Result.Nodes.getNodeAs<NamedDecl>("ImplicitTemplateSpec");
    if (auto DD = Result.Nodes.getNodeAs<DeclaratorDecl>("Decl")) {
      RewriteDeclaratorDecl(Ctx, DD, TemplateSpec);
    } else if (auto DS = Result.Nodes.getNodeAs<DeclStmt>("Stmt")) {
      RewriteDeclStmt(Ctx, DS, TemplateSpec);
    } else {
      assert(false && "Invalid Match");
    }
  }
};

CovertTypeCheck::CovertTypeCheck(
    CovertTypeCheckPolicy Opts,
    llvm::ArrayRef<std::string> QualifierRemovalPatterns) {
  impl = new TypeRewriterCallback(Opts, QualifierRemovalPatterns);
}

CovertTypeCheck::~CovertTypeCheck() { delete impl; }

void CovertTypeCheck::onStartOfTranslationUnit() {
  impl->onStartOfTranslationUnit();
}

void CovertTypeCheck::run(const MatchResultT &Result) { impl->run(Result); }

ICheck::MatcherArrayT CovertTypeCheck::getMatchers() const {
  static const DeclarationMatcher ImplicitTemplateSpecialization =
      namedDecl(anyOf(functionDecl(isFunctionTemplateSpecialization(),
                                   unless(isExplicitTemplateSpecialization())),
                      classTemplateSpecializationDecl(
                          unless(isExplicitTemplateSpecialization()))))
          .bind("ImplicitTemplateSpec");

  static const DeclarationMatcher DeclaredInImplicitTemplateSpecialization =
      anyOf(ImplicitTemplateSpecialization,
            hasAncestor(ImplicitTemplateSpecialization));

  static const ICheck::MatcherT Matchers[] = {
      declaratorDecl(
          anyOf(DeclaredInImplicitTemplateSpecialization, anything()),
          anyOf(varDecl(hasTypeLoc(loc(nonDependentPrimitiveTypeWrapper())),
                        unless(hasParent(declStmt())),
                        unless(allOf(hasStaticStorageDuration(),
                                     hasType(isConstQualified())))),
                fieldDecl(hasTypeLoc(loc(nonDependentPrimitiveTypeWrapper())),
                          unless(isBitField())),
                functionDecl(hasTypeLoc(anything()),
                             returns(nonDependentPrimitiveTypeWrapper()))),
          unless(
              anyOf(declaredInNamespace("covert"), declaredInNamespace("std"))))
          .bind("Decl"),
      declStmt(has(varDecl(
                   anyOf(DeclaredInImplicitTemplateSpecialization, anything()),
                   hasTypeLoc(loc(nonDependentPrimitiveTypeWrapper())),
                   unless(anyOf(declaredInNamespace("covert"),
                                declaredInNamespace("std"))),
                   unless(allOf(hasStaticStorageDuration(),
                                hasType(isConstQualified()))))))
          .bind("Stmt")};

  return Matchers;
}

} // end namespace cpp2covert
} // end namespace covert_tools
