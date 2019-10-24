add_libtool_executable (c2cpp
  CppKeywordCheck.cpp
  CppKeywordCheck.h
  CppImplicitCastCheck.cpp
  CppImplicitCastCheck.h
  CppQualNameCheck.cpp
  CppQualNameCheck.h
  CppCheckFactory.cpp
  CppCheckFactory.h
  C2CPP.cpp
)

target_link_libraries(c2cpp
  Diagnostic
  clangASTMatchers
  ${libtool_libs}
)
