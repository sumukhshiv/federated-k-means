//===------------- __o_impl.h - The O template implementation -------------===//
//
//                           Covert C++ Extensions
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __OBLIVIOUS_O_IMPL_H__
#define __OBLIVIOUS_O_IMPL_H__

#include "omemory.h"
#include <iterator>

#ifndef __cpp_lib_void_t
namespace std {
template <class...> using void_t = void;
}
#endif

namespace oblivious {
namespace __oblivious_impl {

template <typename ContainerT> class __allocator_aware_container_ref {
  using __value_type = typename ContainerT::value_type;
  static_assert(is_oallocator<typename ContainerT::allocator_type>::value, "");

  ContainerT *__container;

public:
  __allocator_aware_container_ref(ContainerT *container)
      : __container(container) {}

  inline __value_type read(const __value_type *addr) const {
    return o_read_list_T(__container->get_allocator().get_regions(), addr,
                         true);
  }
  inline void write(__value_type *addr, const __value_type &val) const {
    o_write_list_T(__container->get_allocator().get_regions(), addr, val, true);
  }
};

template <typename ContainerT> class __static_container_ref {
  ContainerT *__container;
  using __value_type = typename ContainerT::value_type;
  static_assert(alignof(ContainerT) % BLOCK_SIZE == 0,
                "ContainerT must have 64-byte alignment");

public:
  __static_container_ref(ContainerT *c) : __container(c) {}

  inline __value_type read(const __value_type *addr) const {
    return o_read_T(__container->data(), __container->size(), addr, true);
  }
  inline void write(__value_type *addr, const __value_type &val) const {
    o_write_T(__container->data(), __container->size(), addr, val, true);
  }
};

template <typename T, std::size_t N> class __static_container_ref<T[N]> {
  T (*__array)[N];

public:
  __static_container_ref(T (*array)[N]) : __array(array) {}

  inline T read(const T *addr) const { return o_read_T(__array, N, addr); }
  inline void write(T *addr, const T &val) const {
    o_write_T(__array, N, addr, val);
  }
};

template <typename, typename = std::void_t<>>
struct is_allocator_aware : std::false_type {};
template <typename T>
struct is_allocator_aware<
    T, std::void_t<decltype(std::declval<T &>().get_allocator())>>
    : std::true_type {};

template <typename _ContainerT>
using __container_ref =
    typename std::conditional<is_allocator_aware<_ContainerT>::value,
                              __allocator_aware_container_ref<_ContainerT>,
                              __static_container_ref<_ContainerT>>::type;

template <typename _ThisT, typename _IterT> class __o_base;

template <typename _IterT, typename _ContainerT>
class __o_base<O<_IterT, _ContainerT>, typename _ContainerT::iterator> {
  using __ThisT = O<_IterT, _ContainerT>;
  friend class __o_base<O<typename _ContainerT::const_iterator, _ContainerT>,
                        typename _ContainerT::const_iterator>;

protected:
  _IterT __iter;
  __container_ref<_ContainerT> __container;

  __o_base() : __iter(), __container(nullptr) {}
  __o_base(const _IterT &iter, _ContainerT *container)
      : __iter(iter), __container(container) {}
};

template <typename _IterT, typename _ContainerT>
class __o_base<O<_IterT, _ContainerT>, typename _ContainerT::const_iterator> {
  using __ThisT = O<_IterT, _ContainerT>;

protected:
  _IterT __iter;
  __container_ref<_ContainerT> __container;

public:
  __o_base(const _IterT &iter, _ContainerT *container)
      : __iter(iter), __container(container) {}
  __o_base(const __o_base<O<typename _ContainerT::iterator, _ContainerT>,
                          typename _ContainerT::iterator> &other)
      : __iter(other.__iter), __container(other.__container) {}
};

template <typename _ThisT, typename _IteratorCategory> class __o_operators;

template <typename _IterT, typename _ContainerT>
class __o_operators<O<_IterT, _ContainerT>, std::forward_iterator_tag>
    : public __o_base<O<_IterT, _ContainerT>, _IterT> {
protected:
  using __ThisT = O<_IterT, _ContainerT>;
  using __o_base<__ThisT, _IterT>::__o_base;

public:
  friend bool
  operator==(const __o_operators<__ThisT, std::forward_iterator_tag> &o1,
             const __o_operators<__ThisT, std::forward_iterator_tag> &o2) {
    return o1.__iter == o2.__iter;
  }
  friend bool
  operator==(const _IterT &i,
             const __o_operators<__ThisT, std::forward_iterator_tag> &o) {
    return i == o.__iter;
  }
  friend bool
  operator==(const __o_operators<__ThisT, std::forward_iterator_tag> &o,
             const _IterT &i) {
    return o.__iter == i;
  }
  inline __ThisT &operator++() {
    ++this->__iter;
    return static_cast<__ThisT &>(*this);
  }
  inline __ThisT operator++(int) {
    __ThisT ret = static_cast<const __ThisT &>(*this);
    this->__iter++;
    return ret;
  }
};

template <typename _IterT, typename _ContainerT>
bool operator!=(
    const __o_operators<O<_IterT, _ContainerT>, std::forward_iterator_tag> &o1,
    const __o_operators<O<_IterT, _ContainerT>, std::forward_iterator_tag>
        &o2) {
  return !(o1 == o2);
}
template <typename _IterT, typename _ContainerT>
bool operator!=(
    const _IterT &i,
    const __o_operators<O<_IterT, _ContainerT>, std::forward_iterator_tag> &o) {
  return !(i == o);
}
template <typename _IterT, typename _ContainerT>
bool operator!=(
    const __o_operators<O<_IterT, _ContainerT>, std::forward_iterator_tag> &o,
    const _IterT &i) {
  return !(o == i);
}

template <typename _IterT, typename _ContainerT>
class __o_operators<O<_IterT, _ContainerT>, std::bidirectional_iterator_tag>
    : public __o_operators<O<_IterT, _ContainerT>, std::forward_iterator_tag> {
  using __ThisT = O<_IterT, _ContainerT>;

protected:
  using __o_operators<__ThisT, std::forward_iterator_tag>::__o_operators;

public:
  inline __ThisT &operator--() {
    --this->__iter;
    return static_cast<__ThisT &>(*this);
  }
  inline __ThisT operator--(int) {
    __ThisT ret = static_cast<const __ThisT &>(*this);
    this->__iter--;
    return ret;
  }
};

template <typename _IterT, typename _ContainerT>
class __o_operators<O<_IterT, _ContainerT>, std::random_access_iterator_tag>
    : public __o_operators<O<_IterT, _ContainerT>,
                           std::bidirectional_iterator_tag> {
  using __ThisT = O<_IterT, _ContainerT>;
  using __difference_type =
      typename std::iterator_traits<_IterT>::difference_type;

protected:
  using __o_operators<__ThisT, std::bidirectional_iterator_tag>::__o_operators;

public:
  inline __ThisT &operator+=(__difference_type n) {
    this->__iter += n;
    return static_cast<__ThisT &>(*this);
  }
  friend __ThisT
  operator+(const __o_operators<__ThisT, std::random_access_iterator_tag> &o,
            __difference_type n) {
    __ThisT ret = static_cast<const __ThisT &>(o);
    ret.__iter += n;
    return ret;
  }
  friend __ThisT
  operator+(__difference_type n,
            const __o_operators<__ThisT, std::random_access_iterator_tag> &o) {
    __ThisT ret = static_cast<const __ThisT &>(o);
    ret.__iter += n;
    return ret;
  }
  inline __ThisT &operator-=(__difference_type n) {
    this->__iter -= n;
    return static_cast<__ThisT &>(*this);
  }
  friend __ThisT
  operator-(const __o_operators<__ThisT, std::random_access_iterator_tag> &o,
            __difference_type n) {
    __ThisT ret = static_cast<const __ThisT &>(o);
    ret.__iter -= n;
    return ret;
  }
  friend __difference_type
  operator-(const __o_operators<__ThisT, std::random_access_iterator_tag> &o1,
            const __o_operators<__ThisT, std::random_access_iterator_tag> &o2) {
    return o1.__iter - o2.__iter;
  }
  friend __difference_type
  operator-(const __o_operators<__ThisT, std::random_access_iterator_tag> &o,
            const _IterT &i) {
    return o.__iter - i;
  }
  friend __difference_type
  operator-(const _IterT &i,
            const __o_operators<__ThisT, std::random_access_iterator_tag> &o) {
    return i - o.__iter;
  }
  friend bool
  operator<(const __o_operators<__ThisT, std::random_access_iterator_tag> &o1,
            const __o_operators<__ThisT, std::random_access_iterator_tag> &o2) {
    return o1.__iter < o2.__iter;
  }
  friend bool
  operator<(const __o_operators<__ThisT, std::random_access_iterator_tag> &o,
            const _IterT &i) {
    return o.__iter < i;
  }
  friend bool
  operator<(const _IterT &i,
            const __o_operators<__ThisT, std::random_access_iterator_tag> &o) {
    return i < o.__iter;
  }
  friend bool
  operator>(const __o_operators<__ThisT, std::random_access_iterator_tag> &o1,
            const __o_operators<__ThisT, std::random_access_iterator_tag> &o2) {
    return o1.__iter > o2.__iter;
  }
  friend bool
  operator>(const __o_operators<__ThisT, std::random_access_iterator_tag> &o,
            const _IterT &i) {
    return o.__iter > i;
  }
  friend bool
  operator>(const _IterT &i,
            const __o_operators<__ThisT, std::random_access_iterator_tag> &o) {
    return i > o.__iter;
  }
};

template <typename _IterT, typename _ContainerT>
bool operator<=(const __o_operators<O<_IterT, _ContainerT>,
                                    std::random_access_iterator_tag> &o1,
                const __o_operators<O<_IterT, _ContainerT>,
                                    std::random_access_iterator_tag> &o2) {
  return !(o1 > o2);
}
template <typename _IterT, typename _ContainerT>
bool operator<=(const __o_operators<O<_IterT, _ContainerT>,
                                    std::random_access_iterator_tag> &o,
                const _IterT &i) {
  return !(o > i);
}
template <typename _IterT, typename _ContainerT>
bool operator<=(const _IterT &i,
                const __o_operators<O<_IterT, _ContainerT>,
                                    std::random_access_iterator_tag> &o) {
  return !(i > o);
}
template <typename _IterT, typename _ContainerT>
bool operator>=(const __o_operators<O<_IterT, _ContainerT>,
                                    std::random_access_iterator_tag> &o1,
                const __o_operators<O<_IterT, _ContainerT>,
                                    std::random_access_iterator_tag> &o2) {
  return !(o1 < o2);
}
template <typename _IterT, typename _ContainerT>
bool operator>=(const __o_operators<O<_IterT, _ContainerT>,
                                    std::random_access_iterator_tag> &o,
                const _IterT &i) {
  return !(o < i);
}
template <typename _IterT, typename _ContainerT>
bool operator>=(const _IterT &i,
                const __o_operators<O<_IterT, _ContainerT>,
                                    std::random_access_iterator_tag> &o) {
  return !(i < o);
}

template <typename _IterT, typename _ContainerT, typename _IteratorCategory,
          typename = void>
class __o_impl;

template <typename _IterT, typename _ContainerT, typename _IteratorCategory>
class __o_impl<
    _IterT, _ContainerT, _IteratorCategory,
    std::enable_if_t<std::is_same_v<_IterT, typename _ContainerT::iterator>>>
    : public __o_operators<O<_IterT, _ContainerT>, _IteratorCategory> {
  using __ThisT = O<_IterT, _ContainerT>;

  class __accessor;

public:
  using difference_type =
      typename std::iterator_traits<_IterT>::difference_type;
  using value_type = typename std::iterator_traits<_IterT>::value_type;
  using pointer = typename std::iterator_traits<_IterT>::pointer;
  using reference = __accessor;
  using iterator_category = _IteratorCategory;

  __o_impl() = default;
  __o_impl(const _IterT &iter, _ContainerT *ctr)
      : __o_operators<__ThisT, iterator_category>(iter, ctr) {}

private:
  class __accessor {
    friend class __o_impl<_IterT, _ContainerT, iterator_category>;

    __container_ref<_ContainerT> __container;
    pointer __address;

    explicit __accessor(const __ThisT &o)
        : __container(o.__container), __address(std::addressof(*o.__iter)) {}
    __accessor &operator=(const __accessor &) = delete;

  public:
    inline __accessor operator=(const value_type &val) const {
      this->__container.write(__address, val);
      return *this;
    }
    inline operator value_type() const {
      return this->__container.read(__address);
    }
  };

  class __unsafe_accessor {
    friend class __o_impl<_IterT, _ContainerT, iterator_category>;

    pointer __address;

    explicit __unsafe_accessor(const __ThisT &o)
        : __address(std::addressof(*o.__iter)) {}
    __unsafe_accessor &operator=(const __unsafe_accessor &) = delete;

  public:
    inline __unsafe_accessor operator=(const value_type &val) const {
      *__address = val;
      return *this;
    }
    inline operator value_type() const { return *__address; }
  };

public:
  inline reference operator*() const {
    return __accessor{static_cast<const __ThisT &>(*this)};
  }
  inline __unsafe_accessor __get_unsafe_accessor() const {
    return __unsafe_accessor{static_cast<const __ThisT &>(*this)};
  }
};

template <typename _IterT, typename _ContainerT, typename _IteratorCategory>
class __o_impl<_IterT, _ContainerT, _IteratorCategory,
               std::enable_if_t<std::is_same_v<
                   _IterT, typename _ContainerT::const_iterator>>>
    : public __o_operators<O<_IterT, _ContainerT>, _IteratorCategory> {
  using __ThisT = O<_IterT, _ContainerT>;

  class __accessor;

public:
  using difference_type =
      typename std::iterator_traits<_IterT>::difference_type;
  using value_type = typename std::iterator_traits<_IterT>::value_type;
  using pointer = typename std::iterator_traits<_IterT>::pointer;
  using reference = __accessor;
  using iterator_category = _IteratorCategory;

  __o_impl() = default;
  __o_impl(const _IterT &iter, _ContainerT *ctr)
      : __o_operators<__ThisT, iterator_category>(iter, ctr) {}
  __o_impl(const __o_impl<typename _ContainerT::iterator, _ContainerT,
                          _IteratorCategory> &other)
      : __o_operators<__ThisT, iterator_category>(other) {}

private:
  class __accessor {
    friend class __o_impl<_IterT, _ContainerT, iterator_category>;

    __container_ref<_ContainerT> __container;
    pointer __address;

    explicit __accessor(const __ThisT &o)
        : __container(o.__container), __address(std::addressof(*o.__iter)) {}
    __accessor &operator=(const __accessor &) = delete;

  public:
    inline __accessor operator=(const value_type &val) const = delete;
    inline operator value_type() const {
      return this->__container.read(__address);
    }
  };

  class __unsafe_accessor {
    friend class __o_impl<_IterT, _ContainerT, iterator_category>;

    pointer __address;

    explicit __unsafe_accessor(const __ThisT &o)
        : __address(std::addressof(*o.__iter)) {}
    __unsafe_accessor &operator=(const __unsafe_accessor &) = delete;

  public:
    inline __unsafe_accessor operator=(const value_type &val) const = delete;
    inline operator value_type() const { return *__address; }
  };

public:
  inline reference operator*() const {
    return __accessor{static_cast<const __ThisT &>(*this)};
  }
  inline __unsafe_accessor __get_unsafe_accessor() const {
    return __unsafe_accessor{static_cast<const __ThisT &>(*this)};
  }
};

template <typename _IterT, typename _ContainerT>
class __o_impl<
    _IterT, _ContainerT, std::random_access_iterator_tag,
    std::enable_if_t<std::is_same_v<_IterT, typename _ContainerT::iterator>>>
    : public __o_operators<O<_IterT, _ContainerT>,
                           std::random_access_iterator_tag> {
  using __ThisT = O<_IterT, _ContainerT>;

  class __accessor;

public:
  using difference_type =
      typename std::iterator_traits<_IterT>::difference_type;
  using value_type = typename std::iterator_traits<_IterT>::value_type;
  using pointer = typename std::iterator_traits<_IterT>::pointer;
  using reference = __accessor;
  using iterator_category = std::random_access_iterator_tag;

  __o_impl() = default;
  __o_impl(const _IterT &iter, _ContainerT *ctr)
      : __o_operators<__ThisT, iterator_category>(iter, ctr) {}

private:
  class __accessor {
    friend class __o_impl<_IterT, _ContainerT, iterator_category>;

    __container_ref<_ContainerT> __container;
    pointer __address;

    explicit __accessor(const __ThisT &o, difference_type n)
        : __container(o.__container), __address(std::addressof(o.__iter[n])) {}
    __accessor &operator=(const __accessor &) = delete;

  public:
    inline __accessor operator=(const value_type &val) const {
      this->__container.write(__address, val);
      return *this;
    }
    inline operator value_type() const {
      return this->__container.read(__address);
    }
  };

  class __unsafe_accessor {
    friend class __o_impl<_IterT, _ContainerT, iterator_category>;

    pointer __address;

    explicit __unsafe_accessor(const __ThisT &o, difference_type n)
        : __address(std::addressof(o.__iter[n])) {}
    __unsafe_accessor &operator=(const __unsafe_accessor &) = delete;

  public:
    inline __unsafe_accessor operator=(const value_type &val) const {
      *__address = val;
      return *this;
    }
    inline operator value_type() const { return *__address; }
  };

public:
  inline reference operator*() const {
    return __accessor{static_cast<const __ThisT &>(*this), 0};
  }
  inline reference operator[](difference_type n) const {
    return __accessor{static_cast<const __ThisT &>(*this), n};
  }
  inline __unsafe_accessor __get_unsafe_accessor(difference_type n = 0) const {
    return __unsafe_accessor{static_cast<const __ThisT &>(*this), n};
  }
};

template <typename _IterT, typename _ContainerT>
class __o_impl<_IterT, _ContainerT, std::random_access_iterator_tag,
               std::enable_if_t<std::is_same_v<
                   _IterT, typename _ContainerT::const_iterator>>>
    : public __o_operators<O<_IterT, _ContainerT>,
                           std::random_access_iterator_tag> {
  using __ThisT = O<_IterT, _ContainerT>;

  class __accessor;

public:
  using difference_type =
      typename std::iterator_traits<_IterT>::difference_type;
  using value_type = typename std::iterator_traits<_IterT>::value_type;
  using pointer = typename std::iterator_traits<_IterT>::pointer;
  using reference = __accessor;
  using iterator_category = std::random_access_iterator_tag;

  __o_impl() = default;
  __o_impl(const _IterT &iter, _ContainerT *ctr)
      : __o_operators<__ThisT, iterator_category>(iter, ctr) {}
  __o_impl(const __o_impl<typename _ContainerT::iterator, _ContainerT,
                          iterator_category> &other)
      : __o_operators<__ThisT, iterator_category>(other) {}

private:
  class __accessor {
    friend class __o_impl<_IterT, _ContainerT, iterator_category>;

    __container_ref<_ContainerT> __container;
    pointer __address;

    explicit __accessor(const __ThisT &o, difference_type n)
        : __container(o.__container), __address(std::addressof(o.__iter[n])) {}
    __accessor &operator=(const __accessor &) = delete;

  public:
    inline __accessor operator=(const value_type &val) const = delete;
    inline operator value_type() const {
      return this->__container.read(__address);
    }
  };

  class __unsafe_accessor {
    friend class __o_impl<_IterT, _ContainerT, iterator_category>;

    pointer __address;

    explicit __unsafe_accessor(const __ThisT &o, difference_type n)
        : __address(std::addressof(o.__iter[n])) {}
    __unsafe_accessor &operator=(const __unsafe_accessor &) = delete;

  public:
    inline __unsafe_accessor operator=(const value_type &val) const = delete;
    inline operator value_type() const { return *__address; }
  };

public:
  inline reference operator*() const {
    return __accessor{static_cast<const __ThisT &>(*this), 0};
  }
  inline reference operator[](difference_type n) const {
    return __accessor{static_cast<const __ThisT &>(*this), n};
  }
  inline __unsafe_accessor __get_unsafe_accessor(difference_type n = 0) const {
    return __unsafe_accessor{static_cast<const __ThisT &>(*this), n};
  }
};

template <typename _IterT, typename _ContainerT>
using __o = __o_impl<_IterT, _ContainerT,
                     typename std::iterator_traits<_IterT>::iterator_category>;

} // namespace __oblivious_impl
} // end namespace oblivious

#endif
