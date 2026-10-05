# brocas

[![CI](https://github.com/wlejon/brocas/actions/workflows/ci.yml/badge.svg)](https://github.com/wlejon/brocas/actions/workflows/ci.yml)

Content-addressed storage (CAS), Merkle DAG manifests, FastCDC chunking, and wire sync library in C++20. Part of the substrate for a cross-platform desktop environment on the [bro](https://github.com/wlejon/bro) app runtime. A standalone C++20 library: no dependency on bro, bronze, or other siblings, its own CMake and ctest.

## Architecture

```
include/brocas/
  cas.h            Umbrella header
  hash.h           Hash256 (32 bytes, hex formatting/parsing, operators, std::hash) & Hasher (BLAKE3)
  fastcdc.h        Fast Content-Defined Chunking with Gear hashing and normalized masks
  store.h          Disk-backed CAS chunk store, sharded layout, atomic writes, GC mark-and-sweep
  manifest.h       Directory & file Merkle DAG, canonical serialization, ingest, checkout, diff
  protocol.h       Wire framing (BRCA magic, CRC32), message types, binary framing parser
  sync.h           Wire sync engine ("send only what receiver lacks"), resumable transfers, transport
```

## Features

- **BLAKE3 Cryptographic Hashing**:
  - Vendored upstream BLAKE3 1.5.0 C implementation under `third_party/blake3/`: portable plus SSE2 / SSE4.1 / AVX2 / AVX-512 (chosen at run time) on x86-64 and NEON on arm64. BLAKE3 is CC0 1.0 or Apache 2.0, at your option; its license is `third_party/blake3/LICENSE`.
  - Strongly typed `Hash256` (32 bytes, hex string conversions, ordering operators, `std::hash`).
  - `Hasher` supporting one-shot hashing, stream hashing, and file hashing.

- **Fast Content-Defined Chunking (FastCDC)**:
  - Gear hash matrix with normalized chunking mask to minimize chunk size variance.
  - Configurable `min_size` (default 16 KiB), `avg_size` (default 64 KiB), `max_size` (default 256 KiB).
  - Stream chunker processing streams and files without loading whole datasets into RAM.
  - Content deduplication: small edits in multi-megabyte files leave >90% of chunks identical.

- **Content-Addressed Store**:
  - Sharded directory structure: `.cas/chunks/ab/cd/<hash>`.
  - Atomic chunk writes via temporary staging and atomic renaming.
  - Automatic deduplication (write-once semantics).
  - Integrity verification on read (detects disk corruption or bit rot).
  - Root registration and Garbage Collection (`collect_garbage()`): mark-and-sweep from registered root manifests to safely reclaim unreferenced chunks.

- **Folder Manifests & Merkle DAG**:
  - Directory and file tree representation with permissions, timestamps, sizes, and symlinks.
  - Large files represented as Merkle trees of FastCDC chunks (`FileManifest`).
  - Canonical, deterministic serialization format (sorted by entry name).
  - `ingest_directory`: recursively ingest directories and return root Merkle hash.
  - `checkout_directory`: extract manifest hash to target directory, restoring contents, permissions, timestamps, and symlinks.
  - `diff_manifests`: diff two manifests to identify added, modified, deleted files and newly needed chunks.

- **Wire Sync Protocol ("Send only what the other side lacks")**:
  - Binary framing over any byte stream / transport (`Magic: BRCA`, type, length, payload, CRC32).
  - Structured messages: `Handshake`, `ManifestRequest`/`Response`, `HaveQuery`/`Response`, `WantChunks`, `ChunkData`, `Complete`, `Error`.
  - Sync engine:
    - Receiver traverses manifests, checks local CAS store, requests only missing chunks.
    - Sender streams only missing chunks.
    - Receiver verifies hashes and writes directly to local store.
    - Resumable transfers: if connection drops mid-transfer, re-running sync checks local store and requests ONLY the remaining unverified chunks.

## Building

There is nothing to fetch: BLAKE3 is vendored, and brocas needs only CMake 3.24+ and a C++20 compiler (MSVC, GCC or Clang).

### Windows (MSVC, Visual Studio generator)

```powershell
cmake -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

### Linux (GCC 12+, Ninja)

```bash
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure
```

### macOS (Apple Clang, Ninja)

```bash
cmake -B build-release -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
ctest --test-dir build-release --output-on-failure
```

## Tests

The test suite runs real ctests that exercise the real OS file system and fail in Release mode (no `assert()`):

- `test_hash`: Official BLAKE3 test vectors, hex conversion round-trips, incremental and file hashing.
- `test_fastcdc`: Gear hash bounds, stream consistency, and content deduplication ratio.
- `test_store`: Atomic chunk storage, sharded path layout, disk corruption detection, root registration, mark-and-sweep garbage collection.
- `test_manifest`: Recursive directory ingestion, Merkle DAG serialization, byte-exact checkout comparison, and manifest diffing.
- `test_sync`: Wire protocol sync, "send only what receiver lacks", interrupted connection simulation (~50% transfer drop), and resuming with only remaining chunks.
- `test_fuzz`: Fuzzing manifest parsers and wire protocol framing parser with corrupted, truncated, and random byte streams.

All tests utilize `ScopedTempDir` and leave no lasting changes on any machine.
