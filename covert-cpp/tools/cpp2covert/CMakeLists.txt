add_libtool_executable (cpp2covert
  Checks/Casting/CastingCheck.cpp
  Checks/Casting/CastingCheck.h
  Checks/Keywords/KeywordCheck.cpp
  Checks/Keywords/KeywordCheck.h
  Checks/Types/TypePrinter.cpp
  Checks/Types/TypePrinter.h
  Checks/Types/TypeTransformer.cpp
  Checks/Types/TypeTransformer.h
  Checks/Types/TypeCheck.cpp
  Checks/Types/TypeCheck.h
  Checks/CovertHeader/CheckCovertHeader.cpp
  Checks/CovertHeader/CheckCovertHeader.h
  CPP2Covert.cpp
)

target_link_libraries(cpp2covert
  Diagnostic
  clangASTMatchers
  ${libtool_libs}
)
