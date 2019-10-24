//===---- CheckCovertHeader.h - Checks for a missing Covert.h include -----===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __CPP2COVERT_CHECK_COVERT_HEADER__
#define __CPP2COVERT_CHECK_COVERT_HEADER__

#include "clang/AST/ASTContext.h"

namespace covert_tools {
namespace cpp2covert {

bool CheckCovertHeader(clang::ASTContext &Ctx, bool LinkedWithCovert);

} // namespace cpp2covert
} // namespace covert_tools

#endif
