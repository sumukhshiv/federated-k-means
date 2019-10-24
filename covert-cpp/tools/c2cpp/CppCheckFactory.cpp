//===---------- CppCheckFactory.cpp - organizes the c2cpp checks ----------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "CppCheckFactory.h"
#include "CppImplicitCastCheck.h"
#include "CppKeywordCheck.h"
#include "CppQualNameCheck.h"

namespace covert_tools {
namespace c2cpp {

std::vector<std::unique_ptr<ICheck>> CppCheckFactory::get(unsigned Checks) {
  std::vector<std::unique_ptr<ICheck>> v;
  if (CppCheck::ImplicitCast & Checks) {
    v.push_back(llvm::make_unique<CppImplicitCastCheck>());
  }
  if (CppCheck::Keyword & Checks) {
    v.push_back(llvm::make_unique<CppKeywordCheck>());
  }
  if (CppCheck::QualName & Checks) {
    v.push_back(llvm::make_unique<CppQualNameCheck>());
  }
  return v;
}

} // end namespace c2cpp
} // end namespace covert_tools
