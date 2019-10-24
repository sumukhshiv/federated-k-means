//===---------- CppCheckFactory.h - organizes the c2cpp checks  -----------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __CPP_CHECK_FACTORY_H__
#define __CPP_CHECK_FACTORY_H__

#include "ICheck.h"

namespace covert_tools {
namespace c2cpp {

enum CppCheck {
  ImplicitCast = 1 << 0, ///< \see CppImplicitCastCheck
  Keyword = 1 << 1, ///< \see CppKeywordCheck
  QualName = 1 << 2, ///< \see CppQualNameCheck
  All = ~0
};

/// Generates checks for refactoring C code into C++ code.
struct CppCheckFactory {
  static std::vector<std::unique_ptr<ICheck>> get(unsigned Checks);
};

} // end namespace c2cpp
} // end namespace covert_tools

#endif
