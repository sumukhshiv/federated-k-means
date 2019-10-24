//===------------- C2CPP.cpp - entry point for the c2cpp tool -------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/**
 * \defgroup REFACTOR_C2CPP c2cpp
 * \ingroup REFACTOR
 *
 * \brief Refactor C code into C++ code.
 *
 * Defines multiple \c ASTMatcher checks which detect casts, names, etc. that
 * are valid in C, but not in C++. Furthermore the checks can suggest code fixes
 * or hints to help make the target C source C++ compliant.
 *
 * Defined in the namespace covert_tools::c2cpp.
 */

#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/Process.h"

#include "CppCheckFactory.h"
#include "Diagnostic/DiagnosticConsumerCOR.h"
#include "Diagnostic/FixItReplacementConsumer.h"

using namespace llvm;
using namespace clang;
using namespace clang::tooling;

static cl::extrahelp CommonHelp{tooling::CommonOptionsParser::HelpMessage};

static cl::OptionCategory C2CPPCategory{"c2cpp common options"};

/// \brief Apply suggested fixes, if possible.
/// \hideinitializer
static cl::opt<bool> ApplyFixes{"fix",
                                cl::desc(
                                    R"(Apply suggested fixes, if possible)"),
                                cl::cat(C2CPPCategory)};

/// \brief YAML file to store suggested fixes in.
/// \hideinitializer
static cl::opt<std::string> ExportFixes{
    "export-fixes",
    cl::desc(
        R"(YAML file to store suggested fixes in. The stored
fixes can be applied to the input source code with
clang-apply-replacements)"),
    cl::value_desc("filename"), cl::cat(C2CPPCategory)};

/// \brief Display the errors from system headers.
/// \hideinitializer
static cl::opt<bool> SystemHeaders{
    "system-headers", cl::desc(R"(Display the errors from system headers.)"),
    cl::init(false), cl::cat(C2CPPCategory)};

/// \brief Regular expression matching the names of the headers to output
/// diagnostics from.
/// \hideinitializer
static cl::opt<std::string> HeaderFilter{
    "header-filter",
    cl::desc(
        R"(Regular expression matching the names of the
headers to output diagnostics from. Diagnostics
from the main file of each translation unit are
always displayed.)"),
    cl::init(""), cl::cat(C2CPPCategory)};

namespace covert_tools {
/// \brief Refactor C code into C++ code.
namespace c2cpp {

/// \brief Filters out diagnostics that we don't care about.
class C2CPPDiagnosticConsumer : public DiagnosticConsumerCOR {
  llvm::Regex *HeaderFilterRegex;
  bool LastErrorRelatesToUserCode;

public:
  C2CPPDiagnosticConsumer(std::unique_ptr<DiagnosticConsumerCOR> Next = nullptr)
      : DiagnosticConsumerCOR(std::move(Next)), HeaderFilterRegex(nullptr),
        LastErrorRelatesToUserCode(false) {}
  ~C2CPPDiagnosticConsumer() {
    if (HeaderFilterRegex) {
      delete HeaderFilterRegex;
    }
  }

  /// \brief Returns \c true if the diagnostic passes the #HeaderFilter regex.
  ///
  /// Also returns \c true if this is a fatal error, or an error that occurred
  /// at an invalid source location.
  bool CheckFilters(DiagnosticsEngine::Level DiagLevel,
                    const Diagnostic &Info) {
    if (DiagLevel == DiagnosticsEngine::Level::Fatal) {
      return true;
    }

    SourceManager &SM = Info.getSourceManager();
    SourceLocation Loc = Info.getLocation();
    if (Loc.isInvalid()) {
      return true;
    }
    if (!SystemHeaders && SM.isInSystemHeader(Loc)) {
      LastErrorRelatesToUserCode = false;
      return false;
    }
    if (!HeaderFilter.empty() && !SM.isInMainFile(Loc)) {
      if (!HeaderFilterRegex) {
        HeaderFilterRegex = new llvm::Regex(HeaderFilter);
      }

      FileID FID = SM.getDecomposedExpansionLoc(Loc).first;
      const FileEntry *File = SM.getFileEntryForID(FID);
      if (!File)
        return false;

      if ((DiagLevel == DiagnosticsEngine::Level::Warning ||
           DiagLevel == DiagnosticsEngine::Level::Error) &&
          !HeaderFilterRegex->match(File->getName())) {
        LastErrorRelatesToUserCode = false;
        return false;
      }
    }

    if ((DiagLevel == DiagnosticsEngine::Level::Warning ||
         DiagLevel == DiagnosticsEngine::Level::Error)) {
      LastErrorRelatesToUserCode = true;
    }

    return LastErrorRelatesToUserCode;
  }
  void BeginSourceFile(const clang::LangOptions &LOpts,
                       const clang::Preprocessor *PP = nullptr) override {
    DiagnosticConsumerCOR::BeginSourceFile(LOpts, PP);
  }
  void EndSourceFile() override { DiagnosticConsumerCOR::EndSourceFile(); }
  void HandleDiagnostic(DiagnosticsEngine::Level DiagLevel,
                        const Diagnostic &Info) override {
    if (!CheckFilters(DiagLevel, Info)) {
      return;
    }

    DiagnosticConsumerCOR::HandleDiagnostic(DiagLevel, Info);
  }
};

std::unique_ptr<DiagnosticConsumer>
getDiagnosticConsumer(clang::DiagnosticOptions &DiagOpts, FileManager &FM) {
  DiagnosticConsumerCORBuilder Builder;
  Builder.Add(llvm::make_unique<C2CPPDiagnosticConsumer>());
  Builder.AddAdaptee(
      llvm::make_unique<TextDiagnosticPrinter>(llvm::outs(), &DiagOpts));
  if (ApplyFixes || !ExportFixes.empty()) {
    Builder.AddAdaptee(
        llvm::make_unique<FixItReplacementConsumer>(FM, ExportFixes));
  }
  return Builder.Get();
}

int C2CPPMain(int argc, const char **argv) {
  using namespace clang::ast_matchers;
  tooling::CommonOptionsParser OptionsParser(argc, argv, C2CPPCategory,
                                             cl::ZeroOrMore);

  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());

  clang::DiagnosticOptions DiagOpts;
  DiagOpts.setFormat(TextDiagnosticFormat::Clang);
  DiagOpts.ShowColors = sys::Process::StandardOutHasColors();
  auto Diag = getDiagnosticConsumer(DiagOpts, Tool.getFiles());
  Tool.setDiagnosticConsumer(Diag.release());

  MatchFinder Finder;
  auto Checks = CppCheckFactory::get(CppCheck::All);
  for (auto &Check : Checks) {
    for (const auto &Matcher : Check->getMatchers()) {
      Finder.addDynamicMatcher(Matcher, Check.get());
    }
  }

  auto Factory = newFrontendActionFactory(&Finder);
  return Tool.run(Factory.get());
}

} // end namespace c2cpp
} // end namespace covert_tools

int main(int argc, const char **argv) {
  return covert_tools::c2cpp::C2CPPMain(argc, argv);
}
