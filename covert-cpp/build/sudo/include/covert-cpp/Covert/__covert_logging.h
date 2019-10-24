//===--- __covert_logging.h - Defines logging utilities for Covert C++ ----===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

////////////////////////////////////////////////////////////////////////////////
// __covert_logging.h
//
// Defines logging utilities for Covert C++
////////////////////////////////////////////////////////////////////////////////

#ifndef __COVERT_LOGGING_H__
#define __COVERT_LOGGING_H__

/*******************************************************************************
 * LabelPrinter
 ******************************************************************************/

#ifdef __LOG_COVERT_CPP__

#include <iostream>

namespace covert {
namespace __covert_logging__ {

template <typename _LabelT, _LabelT... _Ls> struct LabelPrinter {
  static std::ostream &print_labels(std::ostream &out) { return out; }
};
template <typename _Lst> struct LabelListPrinter;
template <typename _LabelT, template <typename, _LabelT...> class _LstT,
          _LabelT... _Ls>
struct LabelListPrinter<_LstT<_LabelT, _Ls...>> {
  static std::ostream &print_labels(std::ostream &out) {
    return out << LabelPrinter<_LabelT, _Ls...>::print_labels;
  }
};

/*******************************************************************************
 * TypePrinter
 ******************************************************************************/

template <typename... _Ts> struct TypePrinter;
template <typename _T> struct TypePrinter_traits;
template <typename _T> struct TypePrinter_ {
  static std::ostream &print_type(std::ostream &out) {
    return out << TypePrinter_traits<_T>::type_name;
  }
};
template <typename _T> struct TypePrinter_cv {
  static std::ostream &print_type(std::ostream &out) {
    return out << TypePrinter_<_T>::print_type;
  }
};
template <typename _T> struct TypePrinter_cv<const _T> {
  static std::ostream &print_type(std::ostream &out) {
    return out << "const " << TypePrinter_<_T>::print_type;
  }
};
template <typename _T> struct TypePrinter_cv<volatile _T> {
  static std::ostream &print_type(std::ostream &out) {
    return out << "volatile " << TypePrinter_<_T>::print_type;
  }
};
template <typename _T> struct TypePrinter_cv<const volatile _T> {
  static std::ostream &print_type(std::ostream &out) {
    return out << "const volatile " << TypePrinter_<_T>::print_type;
  }
};
#define COVERT_LOG_TYPE(T)                                                     \
  template <> struct TypePrinter_traits<T> {                                   \
    static constexpr const char *type_name = #T;                               \
  };
COVERT_LOG_TYPE(char);
COVERT_LOG_TYPE(unsigned char);
COVERT_LOG_TYPE(short);
COVERT_LOG_TYPE(unsigned short);
COVERT_LOG_TYPE(int);
COVERT_LOG_TYPE(unsigned int);
COVERT_LOG_TYPE(long);
COVERT_LOG_TYPE(unsigned long);
COVERT_LOG_TYPE(long long);
COVERT_LOG_TYPE(unsigned long long);
COVERT_LOG_TYPE(bool);
COVERT_LOG_TYPE(float);
COVERT_LOG_TYPE(double);
COVERT_LOG_TYPE(void);
template <typename _T> struct TypePrinter_<_T *> {
  static std::ostream &print_type(std::ostream &out) {
    return out << TypePrinter_cv<_T>::print_type << "*";
  }
};
template <typename _T> struct TypePrinter_<_T &> {
  static std::ostream &print_type(std::ostream &out) {
    return out << TypePrinter_cv<_T>::print_type << " &";
  }
};
template <typename _T> struct TypePrinter_<_T &&> {
  static std::ostream &print_type(std::ostream &out) {
    return out << TypePrinter_cv<_T>::print_type << " &&";
  }
};
template <typename _LabelT, typename _T, _LabelT... _Ls>
struct TypePrinter_<Covert<_LabelT, _T, _Ls...>> {
  static std::ostream &print_type(std::ostream &out) {
    return out << "Covert<" << TypePrinter_cv<_T>::print_type << ", "
               << LabelPrinter<_LabelT, _Ls...>::print_labels << ">";
  }
};
template <typename _T, std::size_t _N> struct TypePrinter_<_T[_N]> {
  static std::ostream &print_type(std::ostream &out) {
    return out << TypePrinter_cv<_T>::print_type << "[" << _N << "]";
  }
};
template <typename _T, std::size_t _N> struct TypePrinter_<_T (*)[_N]> {
  static std::ostream &print_type(std::ostream &out) {
    return out << TypePrinter_cv<_T>::print_type << "(*)[" << _N << "]";
  }
};
template <typename _R, typename... _ArgTs>
struct TypePrinter_<_R (*)(_ArgTs...)> {
  static std::ostream &print_type(std::ostream &out) {
    return out << TypePrinter_cv<_R>::print_type << "(*)("
               << TypePrinter<_ArgTs...>::print_type << ")";
  }
};
template <typename _T> struct TypePrinter<_T> {
  static std::ostream &print_type(std::ostream &out) {
    return out << TypePrinter_cv<_T>::print_type;
  }
};
template <typename _T, typename... _Ts> struct TypePrinter<_T, _Ts...> {
  static std::ostream &print_type(std::ostream &out) {
    return out << TypePrinter_cv<_T>::print_type << ", "
               << TypePrinter<_Ts...>::print_type;
  }
};

/*******************************************************************************
 * Helpers for Logging, Debugging, and Testing
 ******************************************************************************/

static std::ostream *logd = nullptr;

} // end namespace __covert_logging__
} // end namespace covert

#endif // __LOG_COVERT_CPP__

#endif
