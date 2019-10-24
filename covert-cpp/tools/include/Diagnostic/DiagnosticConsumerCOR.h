//===-- DiagnosticConsumerCOR.h - Chain of Responsibility for Diagnostics -===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __DIAGNOSTIC_CONSUMER_COR_H__
#define __DIAGNOSTIC_CONSUMER_COR_H__

#include "clang/Basic/Diagnostic.h"

namespace covert_tools {

/// \brief A \c DiagnosticConsumer that implements the Chain of Responsibility
/// pattern.
///
/// Each virtual function first calls its inherited definition, then calls the
/// same function in DiagnosticConsumerCOR#Next;
class DiagnosticConsumerCOR : public clang::DiagnosticConsumer {
  friend class DiagnosticConsumerCORBuilder;

protected:
  std::unique_ptr<DiagnosticConsumerCOR> Next;

public:
  DiagnosticConsumerCOR(std::unique_ptr<DiagnosticConsumerCOR> Next = nullptr)
      : Next(std::move(Next)) {}
  virtual ~DiagnosticConsumerCOR() = default;

  inline unsigned &getNumErrors() { return NumErrors; }
  inline unsigned &getNumWarnings() { return NumWarnings; }

  /// \brief Callback to inform the diagnostic client that processing
  /// of a source file is beginning.
  virtual void
  BeginSourceFile(const clang::LangOptions &Opts,
                  const clang::Preprocessor *PP = nullptr) override;

  /// \brief Callback to inform the diagnostic client that processing
  /// of a source file has ended.
  virtual void EndSourceFile() override;

  /// \brief Callback to inform the diagnostic client that processing of all
  /// source files has ended.
  virtual void finish() override;

  /// \brief Handle this diagnostic, reporting it to the user or
  /// capturing it to a log as needed.
  virtual void HandleDiagnostic(clang::DiagnosticsEngine::Level DiagLevel,
                                const clang::Diagnostic &Info) override;
};

/// \brief Object adapter which transforms an ordinary \c DiagnosticConsumer
/// into a DiagnosticConsumerCOR.
class DiagnosticConsumerCORAdapter : public DiagnosticConsumerCOR {
protected:
  std::unique_ptr<DiagnosticConsumer> Adaptee;

public:
  DiagnosticConsumerCORAdapter(
      std::unique_ptr<DiagnosticConsumer> Adaptee,
      std::unique_ptr<DiagnosticConsumerCOR> Next = nullptr)
      : DiagnosticConsumerCOR(std::move(Next)), Adaptee(std::move(Adaptee)) {}
  virtual ~DiagnosticConsumerCORAdapter() = default;

  void clear() override { Adaptee->clear(); }
  void BeginSourceFile(const clang::LangOptions &Opts,
                       const clang::Preprocessor *PP = nullptr) override;
  void EndSourceFile() override;
  void finish() override;
  bool IncludeInDiagnosticCounts() const override {
    return Adaptee->IncludeInDiagnosticCounts();
  }
  void HandleDiagnostic(clang::DiagnosticsEngine::Level DiagLevel,
                        const clang::Diagnostic &Info) override;
};

/// \brief Builds `DiagnosticConsumerCOR`s.
///
/// `DiagnosticConsumerCOR`s will be sequenced in the order in which they
/// are added by the builder. The builder assumes ownership of all added
/// consumers until Get() is called, at which point ownership is released.
class DiagnosticConsumerCORBuilder {
  std::unique_ptr<DiagnosticConsumerCOR> DiagConsumer;
  std::unique_ptr<DiagnosticConsumerCOR> *Placeholder;

public:
  DiagnosticConsumerCORBuilder();

  void Add(std::unique_ptr<DiagnosticConsumerCOR> Diag);
  void AddAdaptee(std::unique_ptr<clang::DiagnosticConsumer> Diag);
  std::unique_ptr<DiagnosticConsumerCOR> Get();
};

} // end namespace covert_tools

#endif
