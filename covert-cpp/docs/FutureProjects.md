Future Projects
=======================

The following are several ideas--not necessarily related to research--that
will make Covert C++ better and more accessible to a broad range of users. Each
project is labeled with a tuple (Priority, Proficiency Requirement) where

Priority := [L]ow | [M]edium | [H]igh

Difficulty := [N]ovice | [I]ntermediate | [E]xpert

Add Multi-Threading Support to NVT (M, E)
-----------------------------------------

Add support to the NVT for multi-threaded applications. This is difficult for
a number of reasons. First, consider the following example:
```C++
byte secret[16]; // high
std::mutex m;

bool foo(byte c) {
  bool ret = 0;
  for (int i = 0; i < 16; ++i) {
    m.lock();
    ret |= secret[i] == c;
    m.unlock();
  }
  return ret;
}

int main() {
  std::thread t1(foo, 'j');
  std::thread t2(foo, 'k');
  t1.join();
  t2.join();
}
```
The NVT operates by fixing Low data and fuzzing high data. It reports a success
iff memory accesses (including instruction fetches) do not vary w.r.t. the
high data being fuzzed. This approach only works if there isn't any other
"noise" in the program affecting memory accesses or control flow. But the
introduction of the lock does introduce noise, because factors under control
of the OS determine the control flow of `lock()` and `unlock()`. One solution
would be to blacklist some library functions to exclude them from the analysis.

Add System Call Support to NVT (M, E)
-------------------------------------

It is non-trivial to predict if and how a system call may break
noninterference. The NVT currently plays it safe by simply issuing an error and
exiting whenever a system call is invoked by the target application. This
project would entail determing which system calls may be safe to allow, and
under what circustances. Then custom logic would be added to the NVT to accept
those system calls.

Add Path Discovery to NVT (M, E)
--------------------------------

Currently, the NVT works by fixing low data, and fuzzing high data. If memory
access patterns do not vary w.r.t. high data, then the target function(s)
satisfy noninterference. But this is insufficient when low data can also affect
a program's control flow; testing for noninterference against only one fixed set
of low inputs can leave some execution paths unexamined. This project would
entail the addition of a preliminary "discovery" phase, in which all low inputs
are fuzzed. Each time a set of low inputs exposes a new execution path, the tool
will note those low inputs. Then the second "noninterference" phase will fuzz
the high inputs for each set of low inputs noted during the discovery phase.

Add an LLVMConfig.cmake (H, N)
------------------------------

This is a DevOps project which would make it easy for developers to integrate
Covert C++ into existing projects. We would roll the Covert C++ toolchain into a
cmake package, with functions to easily integrate the Covert C++ syntax checker
and refactoring tool into a cmake project. For instance, adding Covert C++
checking to any existing project would be as simple as adding the following
lines (indicated by "+") to an existing cmake file:
```
+ find_package(COVERT_CPP)
add_executable(myprogram
  main.cpp
  support.cpp
)
+ add_covert_cpp_check(myprogram)
```
The COVERT_CPP package would export utility functions such as
`add_covert_cpp_check`, which would add a pre-build syntax check to each source
file built by the target executable or library.

Reduce Dependencies on LLVM (L, N)
----------------------------------

Right now, the Covert C++ toolchain is dependent on LLVM for literally
everything, even though only the refactoring tools and parts of the test suites
actually require LLVM. This is unfortunate for users, because it means that
they need a complete installation (with both binaries AND static libraries!)
in order to use any part of the Covert C++ toolchain. This DevOps project would
reorganize Covert C++'s cmake structure to reduce the dependencies on LLVM as
much as possible.

Configure Covert C++ to use Gitlab CI/CD (M, N)
-----------------------------------------------

Gitlab Continuous Integration and Development (CI/CD) is a framework for
reviewing, testing, and deploying cross-platform programs. It automates a lot
of tedious DevOps work, which will be useful over the long term. More
information can be found
[here](https://about.gitlab.com/features/gitlab-ci-cd/).  Gitlab CI/CD is
closely related to Travis-CI, which is Github's analagous solution. Eventually
we may want to integrate with Travis-CI as well. One of the challenges behind
this project would be to set up a Gitlab runner server.

Make libOblivious Containers Safe (M, I)
----------------------------------------

The libOblivious containers are simply typedefs for their corresponding STL
containers. The only difference is that the oblivious containers use the
libOblivious heap allocator. This does mean that these containers can be used
safely, e.g. via the oblivious algorithms like `ofind_if()`. But safety is not
enforced. For instance, `std::list` has a `merge()` operation which is not
safe. Because `olist` is just a typedef, it inherits this unsafe operation. The
oblvious containers should not allow any unsafe operations. This would
certainly require us to use inheritance rather than a typedef. We could then
follow one or both of the following approaches:
1. Completely disallow the unsafe operations by either not inheriting them (e.g.
   use private inheritance) or explicitly deleting them.
2. Override them with safe implementations. For example, an invocation of
   `olist<T>::%merge` would simply forward the request to `omerge` in the
   `oalgorithm` library.
Either way, we should follow this basic principle: safety first, compatibility
with STL containers second.

Complete the libOblivious Algorithms Library (M, N)
---------------------------------------------------

The libOblivious algorithms library is a safe alternative to the C++ STL
algorithms library ([see here](http://en.cppreference.com/w/cpp/algorithm)).
But it is far from complete. All algorithms which can be implemented
obliviously, should be implemented.

libOblivious Performance Testing (H, N)
---------------------------------------

It would be really really nice for research purposes to have a test suite to
evaluate the performance of libOblivious operations against their analagous STL
operations.
