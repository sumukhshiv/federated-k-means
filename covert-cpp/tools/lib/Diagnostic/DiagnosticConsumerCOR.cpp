//=== DiagnosticConsumerCOR.cpp - Chain of Responsibility for Diagnostics -===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Diagnostic/DiagnosticConsumerCOR.h"

using namespace clang;

namespace covert_tools {

void DiagnosticConsumerCOR::BeginSourceFile(const LangOptions &Opts,
                                            const Preprocessor *PP) {
  DiagnosticConsumer::BeginSourceFile(Opts, PP);
  if (Next)
    Next->BeginSourceFile(Opts, PP);
}

void DiagnosticConsumerCOR::EndSourceFile() {
  DiagnosticConsumer::EndSourceFile();
  if (Next)
    Next->EndSourceFile();
}

void DiagnosticConsumerCOR::finish() {
  DiagnosticConsumer::finish();
  if (Next)
    Next->finish();
}

void DiagnosticConsumerCOR::HandleDiagnostic(DiagnosticsEngine::Level DiagLevel,
                                             const Diagnostic &Info) {
  DiagnosticConsumer::HandleDiagnostic(DiagLevel, Info);
  if (Next)
    Next->HandleDiagnostic(DiagLevel, Info);
}

void DiagnosticConsumerCORAdapter::BeginSourceFile(const LangOptions &Opts,
                                                   const Preprocessor *PP) {
  Adaptee->BeginSourceFile(Opts, PP);
  DiagnosticConsumerCOR::BeginSourceFile(Opts, PP);
}

void DiagnosticConsumerCORAdapter::EndSourceFile() {
  Adaptee->EndSourceFile();
  DiagnosticConsumerCOR::EndSourceFile();
}

void DiagnosticConsumerCORAdapter::finish() {
  Adaptee->finish();
  DiagnosticConsumerCOR::finish();
}

void DiagnosticConsumerCORAdapter::HandleDiagnostic(
    DiagnosticsEngine::Level DiagLevel, const Diagnostic &Info) {
  Adaptee->HandleDiagnostic(DiagLevel, Info);
  DiagnosticConsumerCOR::HandleDiagnostic(DiagLevel, Info);
}

DiagnosticConsumerCORBuilder::DiagnosticConsumerCORBuilder()
    : DiagConsumer(nullptr), Placeholder(&DiagConsumer) {}

void DiagnosticConsumerCORBuilder::Add(
    std::unique_ptr<DiagnosticConsumerCOR> Diag) {
  Placeholder->swap(Diag);
  Placeholder = &(*Placeholder)->Next;
}

void DiagnosticConsumerCORBuilder::AddAdaptee(
    std::unique_ptr<DiagnosticConsumer> Diag) {
  Add(llvm::make_unique<DiagnosticConsumerCORAdapter>(std::move(Diag)));
}

std::unique_ptr<DiagnosticConsumerCOR> DiagnosticConsumerCORBuilder::Get() {
  return std::unique_ptr<DiagnosticConsumerCOR>(DiagConsumer.release());
}

} // end namespace covert_tools
