//===-------- CPP2Covert.cpp - Entry point for the cpp2covert tool --------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/**
 * \defgroup REFACTOR_CPP2COVERT cpp2covert
 * \ingroup REFACTOR
 *
 * \brief Refactor C++ code into Covert C++ code.
 *
 * Defines multiple \c ASTMatcher checks which can help a user to translate code
 * that is C++ compliant into code that is C++ compliant.
 *
 * Defined in the namespace covert_tools::cpp2covert.
 */

#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/TextDiagnosticPrinter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/Process.h"

#include "Checks/Casting/CastingCheck.h"
#include "Checks/CovertHeader/CheckCovertHeader.h"
#include "Checks/Keywords/KeywordCheck.h"
#include "Checks/Types/TypeCheck.h"
#include "Diagnostic/DiagnosticConsumerCOR.h"
#include "Diagnostic/FixItReplacementConsumer.h"

using namespace llvm;
using namespace clang;
using namespace clang::tooling;

static cl::extrahelp CommonHelp{tooling::CommonOptionsParser::HelpMessage};

static cl::OptionCategory CPP2CovertCategory{"cpp2covert common options"};

/// \brief Apply suggested fixes, if possible.
/// \hideinitializer
static cl::opt<bool> ApplyFixes{"fix",
                                cl::desc(
                                    R"(Apply suggested fixes, if possible)"),
                                cl::cat(CPP2CovertCategory)};

/// \brief YAML file to store suggested fixes in.
/// \hideinitializer
static cl::opt<std::string> ExportFixes{
    "export-fixes",
    cl::desc(
        R"(YAML file to store suggested fixes in. The stored
fixes can be applied to the input source code with
clang-apply-replacements)"),
    cl::value_desc("filename"), cl::cat(CPP2CovertCategory)};

/// \brief List all supported checks and exit.
/// \hideinitializer
static cl::opt<bool> ListChecks{"list-checks",
                                cl::desc(
                                    R"(List all supported checks and exit.)"),
                                cl::init(false), cl::cat(CPP2CovertCategory)};

/// \brief Indicates that this source file is linked to the 'Covert' interface
/// library.
/// \hideinitializer
static cl::opt<bool> LinkedWithCovert{
    "linked-with-covert",
    cl::desc(
        R"(Enable when the target source file(s) has been linked with the CMake
'Covert' library. E.g. target_link_libraries(<target> Covert))"),
    cl::init(false), cl::cat(CPP2CovertCategory)};

/// \brief Only refactor declarations marked `SECRET`
/// \hideinitializer
static cl::opt<bool> SecretOnly{
    "secret-only",
    cl::desc(
        R"(Only refactor declarations marked 'SECRET')"),
    cl::init(false), cl::cat(CPP2CovertCategory)};

/// \brief Display the errors from system headers.
/// \hideinitializer
static cl::opt<bool> SystemHeaders{
    "system-headers", cl::desc(R"(Display the errors from system headers.)"),
    cl::init(false), cl::cat(CPP2CovertCategory)};

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
    cl::init(""), cl::cat(CPP2CovertCategory)};

/// \brief Comma-separated list of checks to apply.
/// \hideinitializer
static cl::opt<std::string> ChecksStr{
    "checks",
    cl::desc(
        R"(Comma-separated list of checks to apply. Use
"-checks=*" to enable all checks.)"),
    cl::init(""),
    cl::Optional,
    cl::ValueRequired,
    cl::cat(CPP2CovertCategory)};

namespace covert_tools {
/// \brief Refactor C++ code into Covert C++ code.
namespace cpp2covert {

enum Check {
  None = 0,
  Keywords = 1 << 0,
  Types = 1 << 1,
  Casting = 1 << 2,
  All = ~0,
};

using ChecksMap = llvm::StringMap<Check>;

static const ChecksMap &GetChecksMap() {
  static const ChecksMap SupportedChecks = {{"keywords", Check::Keywords},
                                            {"types", Check::Types},
                                            {"casting", Check::Casting}};
  return SupportedChecks;
}

static void printChecks() {
  for (const auto &check : GetChecksMap())
    llvm::outs() << check.first() << '\n';
}

/// Parse a comma-separated string of checks into a vector of checks
static unsigned ParseChecks() {
  using namespace llvm;

  unsigned checks = Check::None;
  if (ChecksStr.empty()) {
    return checks;
  }

  const ChecksMap &SupportedChecks = GetChecksMap();
  const StringRef ArgChecks = ChecksStr;
  StringRef::size_type p = 0, c /* comma */ = ArgChecks.find(',', p);
  while (p != StringRef::npos) {
    StringRef check = ArgChecks.substr(p, c - p);
    if (check == "*") {
      checks = Check::All; // all checks enabled
      break;
    } else {
      ChecksMap::const_iterator I = SupportedChecks.find(check);
      if (I == SupportedChecks.end()) {
        llvm::errs() << "Error: Invalid check '" + check + "'\n";
        exit(1);
      } else {
        checks = checks | I->second;
      }
    }

    if (c == StringRef::npos) {
      p = c;
    } else {
      p = c + 1;
      c = ArgChecks.find(',', p);
    }
  }

  return checks;
}

#define CHECK_ENABLED(checks, check) ((bool)(checks & check))

/// Helper class which filters out irrelevant diagnostics.
class CPP2CovertDiagnosticConsumer : public DiagnosticConsumerCOR {
  std::unique_ptr<llvm::Regex> HeaderFilterRegex;
  bool LastErrorRelatesToUserCode;

public:
  CPP2CovertDiagnosticConsumer(
      std::unique_ptr<DiagnosticConsumerCOR> Next = nullptr)
      : DiagnosticConsumerCOR(std::move(Next)),
        HeaderFilterRegex(!HeaderFilter.empty() ? new llvm::Regex(HeaderFilter)
                                                : nullptr),
        LastErrorRelatesToUserCode(false) {}

  /// Returns true if the diagnostic passes the filter
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
    if (HeaderFilterRegex && !SM.isInMainFile(Loc)) {
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
  void HandleDiagnostic(DiagnosticsEngine::Level DiagLevel,
                        const Diagnostic &Info) override {
    if (!CheckFilters(DiagLevel, Info)) {
      return;
    }
    DiagnosticConsumerCOR::HandleDiagnostic(DiagLevel, Info);
  }
};

static std::unique_ptr<DiagnosticConsumer>
getDiagnosticConsumer(DiagnosticOptions *Opts, FileManager &FM,
                      unsigned Checks = Check::None) {
  DiagnosticConsumerCORBuilder Builder;
  Builder.Add(llvm::make_unique<CPP2CovertDiagnosticConsumer>());
  if (Checks != Check::None && CHECK_ENABLED(Checks, Check::Casting)) {
    Builder.Add(llvm::make_unique<CastingCheck>(nullptr));
  }
  Builder.AddAdaptee(
      llvm::make_unique<TextDiagnosticPrinter>(llvm::outs(), Opts));
  if (ApplyFixes || !ExportFixes.empty()) {
    Builder.AddAdaptee(
        llvm::make_unique<FixItReplacementConsumer>(FM, ExportFixes));
  }
  return Builder.Get();
}

static std::vector<std::string> QualifierRemovalPatterns = {
    "SLabel::", "covert::", "se::"};

static int CPP2CovertMain(int argc, const char **argv) {
  tooling::CommonOptionsParser OptionsParser(argc, argv, CPP2CovertCategory,
                                             cl::ZeroOrMore);
  if (ListChecks) {
    printChecks();
    return 0;
  }

  static unsigned Checks = ParseChecks();
  if (ChecksStr.empty()) {
    llvm::errs() << "Error: No checks specified\n";
    exit(1);
  }

  ClangTool Tool(OptionsParser.getCompilations(),
                 OptionsParser.getSourcePathList());

  FileManager &FM = Tool.getFiles();
  DiagnosticOptions *DiagOpts = new DiagnosticOptions;
  DiagOpts->setFormat(TextDiagnosticFormat::Clang);
  DiagOpts->ShowColors = sys::Process::StandardOutHasColors();
  auto Diag = getDiagnosticConsumer(DiagOpts, FM, Checks);
  Tool.setDiagnosticConsumer(Diag.get());

  std::vector<std::unique_ptr<ASTUnit>> ASTs;
  if (int ret = Tool.buildASTs(ASTs)) {
    Diag->finish();
    return ret;
  }

  ast_matchers::MatchFinder Finder;
  std::vector<std::unique_ptr<ICheck>> Callbacks;
  if (CHECK_ENABLED(Checks, Check::Keywords)) {
    Callbacks.emplace_back(new KeywordCheck());
    for (const auto &Matcher : Callbacks.back()->getMatchers()) {
      if (!Finder.addDynamicMatcher(Matcher, Callbacks.back().get())) {
        assert(false && "Provided an invalid DynTypedMatcher");
      }
    }
  }
  if (CHECK_ENABLED(Checks, Check::Types)) {
    CovertTypeCheckPolicy TypeOpts;
    TypeOpts.RewriteSecretOnly = SecretOnly;
    TypeOpts.LinkedWithCovert = LinkedWithCovert;
    TypeOpts.SuppressUnwrittenScope = true;
    TypeOpts.SuppressScope = true;
    TypeOpts.SuppressTagKeyword = true;
    Callbacks.emplace_back(
        new CovertTypeCheck(TypeOpts, QualifierRemovalPatterns));
    for (const auto &Matcher : Callbacks.back()->getMatchers()) {
      if (!Finder.addDynamicMatcher(Matcher, Callbacks.back().get())) {
        assert(false && "Provided an invalid DynTypedMatcher");
      }
    }
  }

  for (auto &AST : ASTs) {
    ASTContext &Ctx = AST->getASTContext();
    DiagnosticsEngine &DE = Ctx.getDiagnostics();
    DE.setClient(Diag.get(), false /* don't assume ownership */);
    DE.getClient()->BeginSourceFile(Ctx.getLangOpts());
    if (CHECK_ENABLED(Checks, Check::Types) &&
        !CheckCovertHeader(Ctx, LinkedWithCovert)) {
      continue;
    }
    Finder.matchAST(Ctx);
    DE.getClient()->EndSourceFile();
  }

  Diag->finish(); // emit the FixIts

  return 0;
}

} // end namespace cpp2covert
} // end namespace covert_tools

int main(int argc, const char **argv) {
  return covert_tools::cpp2covert::CPP2CovertMain(argc, argv);
}
