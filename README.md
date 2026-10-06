# brocas

[![CI](https://github.com/wlejon/brocas/actions/workflows/ci.yml/badge.svg)](https://github.com/wlejon/brocas/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Content-addressed storage (CAS), Merkle DAG manifests, Fast Content-Defined Chunking (FastCDC),
and wire sync protocol in pure C++20. A standalone library providing efficient deduplication,
resumable delta transfer, and verifiable file tree serialization.

brocas sits in the desktop-environment layer of the
[bro ecosystem](https://github.com/wlejon/bro/blob/main/docs/ecosystem.md). It serves as the
foundational data-storage and synchronization substrate across the ecosystem, designed to
operate independently with zero dependencies on bro, bronze, or other sibling libraries.

## Architecture & API Overview

```
include/brocas/
  cas.h               Umbrella header
  hash.h              Hash256 (32-byte strongly typed hash) and Hasher (BLAKE3)
  fastcdc.h           Fast Content-Defined Chunking (Gear hashing, normalized chunk masks)
  store.h             Disk-backed sharded CAS chunk store, atomic writes, mark-and-sweep GC
  manifest.h          Merkle DAG directory and file manifests, canonical serialization, diff
  protocol.h          Binary wire framing (BRCA magic, CRC32, framing parser, message types)
  sync.h              Sync wire engine ("send only what receiver lacks", resumable transfers)
  socket_transport.h  Stream socket transport interface for network sync
```

### Key Modules

- **BLAKE3 Cryptographic Hashing (`hash.h`):** Vendored upstream BLAKE3 1.5.0
  (`third_party/blake3/`) with automatic SIMD runtime dispatch (SSE2, SSE4.1, AVX2, AVX-512,
  ARM NEON). Provides strongly typed `Hash256` value objects (with hex conversions, ordering,
  and `std::hash`) and `Hasher` for incremental and file streams.
- **Fast Content-Defined Chunking (`fastcdc.h`):** Gear hash matrix with normalized chunking
  masks to minimize chunk size variance. Configurable `min_size` (default 16 KiB), `avg_size`
  (default 64 KiB), and `max_size` (default 256 KiB). Small localized edits in multi-megabyte
  files leave >90% of chunks identical.
- **Content-Addressed Store (`store.h`):** Disk-backed chunk repository with a sharded
  two-level directory structure (`.cas/chunks/ab/cd/<hash>`). Writes stage to temporary files
  and commit with atomic renames. Detects corruption or bit rot on read. Mark-and-sweep
  garbage collection (`collect_garbage()`) reclaims unreferenced chunks from registered root
  manifests.
- **Merkle DAG Manifests (`manifest.h`):** Directory and file tree representations capturing
  file modes, permissions, timestamps, sizes, and symlink targets. Large files are chunked
  into Merkle trees of FastCDC chunks (`FileManifest`). Deterministic canonical serialization
  guarantees identical hash trees for identical directory states. Supports `ingest_directory()`,
  `checkout_directory()`, and `diff_manifests()`.
- **Wire Framing & Sync Protocol (`protocol.h`, `sync.h`):** Binary framing over arbitrary
  byte streams with `BRCA` magic, packet headers, length fields, and CRC32 payload checksums.
  The sync engine executes a "send only what the receiver lacks" protocol: the receiver
  evaluates the Merkle manifest against its local CAS store, requests only missing hashes, and
  verifies incoming chunks before committing. Transfers interrupted mid-flight resume by
  querying the store, never re-transmitting already committed chunks.

## Platforms

brocas is pure C++20 and has been tested and verified across all major desktop and server
operating systems:

| Platform | Compiler | SIMD Acceleration | Verified Architectures |
|---|---|---|---|
| **Windows** | MSVC 2022+ | SSE2, SSE4.1, AVX2, AVX-512 run-time dispatch | x86-64 |
| **Linux** | GCC 12+, Clang 15+ | SSE2, SSE4.1, AVX2, AVX-512 run-time dispatch | x86-64, aarch64 (NEON) |
| **macOS** | Apple Clang (Xcode 14+) | ARM NEON vector instructions; x86-64 SSE/AVX | Apple silicon (arm64), x86-64 |

SIMD acceleration targets are compiled into the BLAKE3 static object and selected dynamically
at runtime via CPU feature discovery. On unsupported architectures, an optimized pure C
portable implementation is selected automatically.

## Building

brocas requires CMake 3.24+ and a C++20 compiler. BLAKE3 is vendored in `third_party/blake3/`;
there are no external third-party dependencies to install.

### Standalone Build

```bash
# Linux (GCC / Clang + Ninja)
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure

# Windows (MSVC, Visual Studio 2022 or Ninja)
cmake -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure

# macOS (Apple Clang + Ninja)
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure
```

### Consuming brocas as a Dependency

Downstream consumers embed or link `brocas::brocas`:

```cmake
add_subdirectory(path/to/brocas)
target_link_libraries(your_target PRIVATE brocas::brocas)
```

On Windows, `brocas::brocas` automatically exports a private dependency on `ws2_32` for
network socket transport.

In accordance with the ecosystem convention, consumers can locate `brocas` via:
1. **Sibling checkout (development default):**
   ```bash
   git clone https://github.com/wlejon/brocas   # checked out next to consumer at ../brocas
   ```
2. **Submodule layout (isolated / CI builds):**
   ```bash
   git clone --recursive https://github.com/wlejon/consumer_repo
   # or add as submodule:
   git submodule add https://github.com/wlejon/brocas.git third_party/brocas
   ```

## Tests

The test suite runs real ctests executing against isolated temporary scratch directories
(`ScopedTempDir`) and verifies behavior in both Debug and Release modes without assertions in
library code:

- **`test_hash`:** Validates against official BLAKE3 test vectors, verifies hex serialization
  and deserialization round-trips, tests incremental multi-buffer hashing, and exercises file
  stream hashing.
- **`test_fastcdc`:** Asserts Gear hash bounds, validates stream chunk boundary consistency,
  and measures content deduplication efficiency across mutated test buffers.
- **`test_store`:** Tests atomic chunk write staging, two-level sharded directory layout,
  detection of simulated bit rot and disk corruption, manifest root registration, and
  mark-and-sweep garbage collection.
- **`test_manifest`:** Recursively ingests deep directory trees, verifies deterministic
  Merkle DAG serialization, performs byte-exact checkout comparison (preserving file contents,
  permissions, timestamps, and symlinks), and diffs manifests across tree mutations.
- **`test_sync`:** Simulates end-to-end wire protocol synchronization, validates that the
  sender transmits only chunks the receiver lacks, simulates broken connections (~50% wire
  drop), and verifies that sync resumes seamlessly by requesting only unverified chunks.
- **`test_fuzz`:** Fuzzes manifest parsers and the binary wire framing state machine with
  truncated, corrupted, malformed, and random byte streams.

All tests clean up their temporary files on completion with zero machine leftovers.
