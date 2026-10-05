cmake_minimum_required(VERSION 3.24)

project(brocas VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(_brocas_top_level OFF)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(_brocas_top_level ON)
endif()

option(BROCAS_BUILD_TESTS "Build brocas tests" ${_brocas_top_level})

# Coverage. Scoped to a top-level build: a consumer that add_subdirectory()s
# brocas has no business having its own build instrumented from in here.
option(BROCAS_COVERAGE "Instrument the build for gcov coverage (GCC/Clang)" OFF)
if(BROCAS_COVERAGE AND _brocas_top_level)
    if(MSVC)
        message(FATAL_ERROR "BROCAS_COVERAGE requires GCC or Clang (gcov instrumentation); MSVC is unsupported.")
    endif()
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
    message(STATUS "brocas: coverage instrumentation ON (-O0)")
endif()

function(brocas_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /MP)
        target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

# Vendored BLAKE3
set(BLAKE3_SOURCES
    third_party/blake3/blake3.c
    third_party/blake3/blake3_dispatch.c
    third_party/blake3/blake3_portable.c
)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)")
    list(APPEND BLAKE3_SOURCES third_party/blake3/blake3_neon.c)
    add_library(blake3 STATIC ${BLAKE3_SOURCES})
    target_compile_definitions(blake3 PRIVATE BLAKE3_USE_NEON=1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)" OR (MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8))
    list(APPEND BLAKE3_SOURCES
        third_party/blake3/blake3_sse2.c
        third_party/blake3/blake3_sse41.c
        third_party/blake3/blake3_avx2.c
        third_party/blake3/blake3_avx512.c
    )
    add_library(blake3 STATIC ${BLAKE3_SOURCES})
    if(MSVC)
        set_source_files_properties(third_party/blake3/blake3_sse2.c PROPERTIES COMPILE_FLAGS "/arch:SSE2")
        set_source_files_properties(third_party/blake3/blake3_sse41.c PROPERTIES COMPILE_FLAGS "/arch:AVX")
        set_source_files_properties(third_party/blake3/blake3_avx2.c PROPERTIES COMPILE_FLAGS "/arch:AVX2")
        set_source_files_properties(third_party/blake3/blake3_avx512.c PROPERTIES COMPILE_FLAGS "/arch:AVX512")
    else()
        set_source_files_properties(third_party/blake3/blake3_sse2.c PROPERTIES COMPILE_FLAGS "-msse2")
        set_source_files_properties(third_party/blake3/blake3_sse41.c PROPERTIES COMPILE_FLAGS "-msse4.1")
        set_source_files_properties(third_party/blake3/blake3_avx2.c PROPERTIES COMPILE_FLAGS "-mavx2")
        set_source_files_properties(third_party/blake3/blake3_avx512.c PROPERTIES COMPILE_FLAGS "-mavx512f -mavx512vl")
    endif()
else()
    add_library(blake3 STATIC ${BLAKE3_SOURCES})
    target_compile_definitions(blake3 PRIVATE
        BLAKE3_NO_AVX512
        BLAKE3_NO_AVX2
        BLAKE3_NO_SSE41
        BLAKE3_NO_SSE2
        BLAKE3_USE_NEON=0
    )
endif()

target_include_directories(blake3 PUBLIC third_party/blake3)
if(MSVC)
    target_compile_definitions(blake3 PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Brocas library
set(BROCAS_SOURCES
    src/hash.cpp
    src/fastcdc.cpp
    src/store.cpp
    src/manifest.cpp
    src/manifest_ingest.cpp
    src/manifest_checkout.cpp
    src/manifest_diff.cpp
    src/protocol.cpp
    src/sync.cpp
    src/socket_transport.cpp
)

add_library(brocas STATIC ${BROCAS_SOURCES})
add_library(brocas::brocas ALIAS brocas)

target_include_directories(brocas
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/blake3
)

target_link_libraries(brocas PRIVATE blake3)
if(WIN32)
    target_link_libraries(brocas PUBLIC ws2_32)
endif()
brocas_warnings(brocas)

if(WIN32)
    target_compile_definitions(brocas PUBLIC
        NOMINMAX
        WIN32_LEAN_AND_MEAN
        UNICODE
        _UNICODE
    )
endif()

if(BROCAS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
