Language Reference
=======================

Public Covert C++ definitions exist in the `covert` namespace.

Security Levels
-----------------------

Security levels are either low (public) or high (secret).
```C++
enum SLevel { L, H };
```

The **least upper bound (LUB)** of two security levels S1 and S2 is high if either
S1 or S2 is high.

A **security level list** is a sequence of security levels [S0, S1, ..., Sn].

A security level list [S0, S1, ..., Sn] is **less than or equal to (<=)** a
security level list [T0, T1, ..., Tm] if, for all i <= min(n, m), Si <= Ti.

TODO:

 * - `pfx_to_primitive()`: Cast `Covert<LabelT, Labels...>` --> `LabelT`
 * - `pfx_guard<Labels...>()`: Returns the argument value, but only compiles if
 *   the argument's labels are all less than or equal to `Labels...`,
 *   respectively.
 * - `pfx_label_cast<DataRetT, RetLabels...>()`: Cast `Covert<DataT, Labels...>` -->
 *   `Covert<DataRetT', RetLabels...>`. There are no restrictions on `RetLabels...`, so
 *   long as the number of labels is appropriate for the type_depth of `DataT`.
 *   If `DataRetT` is cv-qualified and/or is a reference, 
