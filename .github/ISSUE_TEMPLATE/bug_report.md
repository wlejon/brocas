---
name: Bug report
about: A wrong hash, a corrupt or lost chunk, a checkout that differs from what was ingested, a sync that sends too much or fails, or a crash
labels: bug
---

**What went wrong** (pick the closest): wrong hash / chunk boundaries differ
from the reference / store lost or corrupted data / checkout differs from the
ingested tree / sync transferred chunks the receiver had / sync failed or did
not resume / parser crash on malformed input / other.

**The calls or data that reproduce it** (smallest you can manage; for a parser
crash, the bytes as hex or an attached file):

```cpp
```

**What should have happened:**

**What brocas did instead** (the `Result` error, a crash, or the failing
`ctest --output-on-failure` output — paste it):

```
```

**Environment:**
- OS and version, CPU (x86-64 with AVX2 / AVX-512, or arm64):
- Compiler / toolchain (MSVC / GCC / Clang):
- brocas commit:
