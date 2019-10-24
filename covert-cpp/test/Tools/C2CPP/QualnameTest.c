// RUN: %check-c2cpp --

typedef struct M {
  int k;
} m;

struct SomeItem {
  enum T {MOVIE, MUSIC} itemType;
  struct Inner {
    struct DoubleInner {
      int a;
    } DI;
    union DoubleInnerU {
      int m;
      char *n;
    } DIU;
    struct {
      int k;
    } Anon;
  } I;
};

int main() {
  enum T item = (enum T)MOVIE;
// CHECK-MESSAGES: :[[@LINE-1]]:8: warning: 'T' must be qualified in C++
// CHECK-MESSAGES: :[[@LINE-2]]:23: warning: 'T' must be qualified in C++
// CHECK-MESSAGES: :[[@LINE-3]]:25: warning: 'MOVIE' must be qualified in C++
// CHECK-FIXES: enum SomeItem::T item = (enum SomeItem::T)SomeItem::MOVIE;
  const struct DoubleInner *blah;
// CHECK-MESSAGES: :[[@LINE-1]]:16: warning: 'DoubleInner' must be qualified in C++
// CHECK-FIXES: const struct SomeItem::Inner::DoubleInner *blah;
  union DoubleInnerU blahU;
// CHECK-MESSAGES: :[[@LINE-1]]:9: warning: 'DoubleInnerU' must be qualified in C++
// CHECK-FIXES: union SomeItem::Inner::DoubleInnerU blahU;
#define UNION(name) union DoubleInnerU name;
  UNION(blahU2);
// CHECK-MESSAGES: :[[@LINE-1]]:3: warning: 'DoubleInnerU' must be qualified in C++
// CHECK-MESSAGES: :[[@LINE-3]]:27: note: expanded from macro 'UNION'
// CHECK-MESSAGES: :[[@LINE-4]]:27: note: use 'SomeItem::Inner::DoubleInnerU' instead
  m my_m;

  return 0;
}
