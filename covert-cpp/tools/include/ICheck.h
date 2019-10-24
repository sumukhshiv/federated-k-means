//===---------- ICheck.h - Interface for refactoring tool checks ----------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __ICHECK_H__
#define __ICHECK_H__

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "llvm/ADT/ArrayRef.h"

namespace covert_tools {

/// \brief Interface to a check which combines the callback and the AST
/// matchers.
///
/// Intended for use by a \c MatchFinder. e.g.
/// \code
/// MatchFinder Finder;
/// ICheck *Check = getMyCheck();
/// for (const auto &Matcher : Check->getMatchers()) {
///   Finder.addDynamicMatcher(Matcher, Check);
/// }
/// \endcode
struct ICheck : public clang::ast_matchers::MatchFinder::MatchCallback {
  using MatchResultT = clang::ast_matchers::MatchFinder::MatchResult;
  using MatcherT = clang::ast_matchers::internal::DynTypedMatcher;
  using MatcherArrayT = llvm::ArrayRef<const MatcherT>;

  /// Called on every match by the \c MatchFinder.
  virtual void run(const MatchResultT &Result) = 0;
  /// Return the AST matchers used by this check
  virtual MatcherArrayT getMatchers() const = 0;
};

} // end namespace covert_tools

#endif
