Tutorial
=======================

Part 1: Intro to Covert C++
---------------------------

In Covert C++, all program data has an associated security label, either low
(`L`) or high (`H`). In general, low data is public, and high data is secret.
We can associate a data type with a security label as follows:
```C++
using l_int = SE<int, L>;
using h_int = SE<int, H>;
using lh_ptr = SE<const int *, L, H>; // points to a high const int
using hl_ptr = SE<int *, H, L>; // high pointer, pointing to a low int
```
`SE` is a templatized wrapper which associates a data type `T` with a
security label. `SE<T, [...]>` contains exactly one member of type `T`, whose
behavior may be constrained by the associated security label(s) `[...]`. The
basic typing rules for Covert C++ can be summarized as follows:
1. Plain (unwrapped) data can be implicitly converted into `L` data, and
   vice-versa.
    1. `L` data can be implicitly converted into `H` data.
    2. `H` data cannot be implicitly converted into `L` data.
2. Operators which “combine” security-typed data propagate the respective labels
by computing their LUB. In these operations, primitive data is treated as though
it is L data.
3. Taking the address (`&`) of a variable of type `SE<T, S1, [...]>` produces
   a pointer of type `SE<T *, L, S1, [...]>`.
4. `H` pointers cannot be dereferenced or subscripted. A pointer of type
   `SE<T *, L, [...]>` may be dereferenced or subscripted with result type
   `SE<T, [...]>` or `T` if [...] was empty.

The following example illustrates these rules:
```C++
int _x = 42;
SE<int, L> l = _x;          // ok by rule 1
SE<int, H> h = _x;          // ok by rules 1 and 1.1
l = h;                      // ERROR: violates rule 1.2
auto sum = l + h;           // sum has type SE<int, H>, by rule 2
SE<int *, L, H> lhp = &h;   // ok by rule 3
SE<int *, H, H> hhp = lhp;  // ok by rule 1.1
*lhp;                       // ok
(*hhp)++;                   // ERROR: violates rule 4
h = hhp[0];                 // ERROR: violates rule 4
```
Note that these typing rules only present an informal summary of the actual
Covert C++ typing rules. Additional typing rules can be found in the [Language Reference](LanguageReference.md).

Covert C++ guards against side-channel attacks primarily by enforcing rules
1, 1.2, and 4. Consider the following simple example:
```C++
void foo(SE<bool, H> secret_bool) {
  if (secret_bool) { // ERROR: violates rule 1.2
    do_thing1();
  } else {
    do_thing2();
  }
}
```
If the adversary is able to observe the control flow of the program (e.g. via
page fault patterns), he/she may be able to observe whether `do_thing1()` or
`do_thing2()` has been called, and thus infer the value of `secret_bool` to be
`true` or `false`, respectively. However, the typing rules of Covert C++ will
not allow this program to compile. The reason is that C++ requires that the
branching condition for a selection statement (e.g. `for`, `while`, `if`,
`else if`, `do while`, `switch`) be contextually convertible to a plain type,
such as `bool` or an arithmetic type. By rule 1.2, `secret_bool` cannot
implicitly convert to `L`--and thus to a plain type--because `secret_bool`
is high. Hence the compiler will issue an error diagnostic. One possible
strategy for eliminating this kind of side-channel within the bounds of
Covert C++ typing is discussed in Part 2 of the tutorial.

Program control flow is not the only mechanism by which an adversary can infer
sensitive data by viewing a side-channel. An adversary who can view the
sequence of memory accesses to some degree of granularity may also be able to
infer sensitive data. For instance,
```C++
SE<int, L> array[1024];
SE<std::size_t, H> secret = 137;

template <typename T>
SE<int, L> read(T val) {
  return array[val];
}

int main() {
  read(secret);
}
```
An adversary who can observe memory access addresses with at least word-size
granularity will be able to observe the address of `array` which was accessed
by `read()`, and thus deduce the value of `secret` to be `137`.

Part 2: Secure `memcmp()`
-------------------------

Consider this typical definition of `memcmp()`:
```C++
int memcmp(const void *b1, const void *b2, std::size_t n) {
  const uint8_t *s1 = (const uint8_t *)b1, *s2 = (const uint8_t *)b2;
  while (n--) {
    int diff = *s1++ - *s2++;
    if (diff) {
      return diff;
    }
  }
  return 0;
}
```
The loop iterates at most `n` times through the two buffer arguments, increasing
the `s1` and `s2` pointers by 1 byte on each iteration. As soon as a difference
is found between the two buffers, `memcmp()` returns the (non-zero) difference
of the two corresponding bytes which did not match. Otherwise, the loop
exits and `memcmp()` returns `0`.

Although this definition of `memcmp()` is correct, it does have a side-channel
vulnerability. Suppose that `memcmp()` is being used to compare a secret key
against an input taken from the keyboard, possibly from a user with malicious
intent. Suppose that the key is 128-bit, or 16 bytes long. Ideally it should
require at most 2^128 to guess the right key. However, if the malicious user is
able to observe some aspect of the computation other than the integer
difference result, then he/she might be able to gain an advantage. For
instance, if the attacker can infer the control flow of the program, he/she may
observe when exactly the loop terminates and returns `true`. In this scenario,
the malicious user would begin by trying all 256 permutations of the first byte
until `memcmp()` runs for just one more iteration, and then he/she would repeat
this strategy for the remaining 15 bytes. By following this strategy, the
attacker would require only at most 256*16 = 2^12 attempts, far better than the
2^128 required by brute force.

The same `memcmp()` function expressed with Covert C++ typing is given below:
```C++
SE<bool, L> memcmp(SE<const uint8_t *, L, L> s1, SE<const uint8_t *, L, L> s2,
                   SE<std::size_t, L> n) {
#ifndef __NO_OUTPUT__
  std::cout << "Call to optimized memcmp()\n";
#endif
  while (n--) {
    SE<int, L> diff = *s1++ - *s2++;
    if (diff)
      return diff;
  }
  return 0;
}
```
The only semantic difference is that the two buffer arguments have now been
given type `const uint8_t *` instead of `const void *`. This is because `void *`
is weakly typed; a pointer with this type could in fact be pointing to anything.
So Covert C++ only labels the pointer itself, and makes no assumptions about
what it may be pointing to. Hence if we wish to define a `memcmp()` operation
on high buffers (pointers pointing to high data), we cannot express this with
`void` pointers. Instead, we opt for the `uint8_t`, a.k.a. `unsigned char` type.

Note that all arguments are low and/or point to low, so Covert C++ should not
complain about any type rule violations. Indeed it does not.

How can we write a version of `memcmp()` which is semantically equivalent, but
can be safely invoked on high buffers?
```C++
SE<bool, H> memcmp(SE<const uint8_t *, L, H> s1, SE<const uint8_t *, L, H> s2,
                   SE<std::size_t, L> n) {
#ifndef __NO_OUTPUT__
  std::cout << "Call to secure memcmp()\n";
#endif
  SE<int, H> ret = 0;
  while (n--) {
    SE<int, H> diff = *s1++ - *s2++;
    ret = covert::ternary(diff != 0 & ret == 0, diff, ret);
  }
  return ret;
}
```
First note that `s1` and `s2` may point to high buffers. Second, examine the
heuristic deployed in the `while` loop. The high integer `ret` is initialized
to `0`. On each iteration, the contents at `s1` and `s2` are compared using the
`!=` operator, as in the prior implementation. The `covert::ternary()` function
is similar to the `?:` ternary operator in C++, except that the value of the
condition argument is not leaked through a side channel. If the first argument
evaluates to `true` (or not `0`), the second argument is returned; otherwise
the third argument is returned. So if the `diff` is non-zero and we have not
already recorded a non-zero diff, then `ret` is updated to `diff`.  Otherwise
`ret` is unchanged.

Take a moment to convince yourself that this "secure" `memcmp()` really does
have the same semantic behavior of the "optimized" `memcmp()` implementation
above. This version is secure because the high buffer data does not influence
control flow, nor memory accesses. The loop will always run `n` times, and
touch the same buffer addresses in the same sequence, regardless of the
contents of the buffers. Finally, note that `ret` must be high, because rules 2
and 4 dictate that the expression `*s1++ != *s2++` must be high.

One beautiful feature of Covert C++ is that the developer does not need to
manually choose between the secure and optimized versions of `memcmp()`. This
can be done automatically by C++ overload resolution.
```C++
SE<const char *, L, H> secret = "This is the secret";
SE<const char *, L, L> input = "This is NOT the secret";
auto _secret = se_reinterpret_cast<const uint8_t *, L, H>(secret);
auto _input = se_reinterpret_cast<const uint8_t *, L, L>(input);

std::cout << "Testing with secret input...\n";
if (se_label_cast<bool, L>(!memcmp(_secret, _input, sz))) {
  std::cout << "You got it!\n";
} else {
  std::cout << "You didn't get it!\n";
}
```
Which `memcmp()` should be called? There is actually only one option for the
compiler: the secure `memcmp()`. This is because, by rule 1.2, `_secret` cannot
by converted to the low input required by the optimized `memcmp`. By rule 1.1,
`_input` can be converted to the high input required by the secure `memcmp()`.
So since all arguments can convert to the types required by secure `memcmp()`,
the C++ compiler will use that version.

The only exception to rule 1.2 is the `se_label_cast()` operator, which can
"downcast" security labels. Here, we use it to make a branch decision based
on the result of the call to `memcmp()`. The `se_label_cast()` operator should be
used sparingly, and only after carefully considering the consequences of
downgrading a value's security label, which essentially discloses the value.
Here, the use of `se_label_cast()` is acceptable because it reveals nothing other
than whether the two buffers were equal.

What if `memcmp()` is called with two low buffers?
```C++
std::cout << "Testing with public input...\n";
auto _disclosed_secret = se_label_cast<const uint8_t *, L, L>(_secret);
if (!memcmp(_disclosed_secret, _input, sz)) {
  std::cout << "You got it!\n";
} else {
  std::cout << "You didn't get it!\n";
}
```
Now both `memcmp()` functions are candidates, but the optimized one matches
more closely. That is, the compiler needs to perform fewer type conversions in
order to match the arguments. So the optimized `memcmp()` will be called, as
expected. Also note that here we did not required the `slevel_cast`, because
the result of the optimized `memcmp()` operation is already low.

**Note:** The source code for this tutorial can be found in `examples/memcmp/`.
It can be built by making the `example-memcmp-run` target.
