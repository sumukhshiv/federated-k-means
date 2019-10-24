add_llvm_library (Diagnostic
  STATIC BUILDTREE_ONLY EXCLUDE_FROM_ALL
  DiagnosticConsumerCOR.cpp
  FixItReplacementConsumer.cpp

  # header files
  ${COVERT_TOOLS_INCLUDE_DIR}/Diagnostic/DiagnosticConsumerCOR.h
  ${COVERT_TOOLS_INCLUDE_DIR}/Diagnostic/FixItReplacementConsumer.h
)
