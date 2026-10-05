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

add_library(blake3 STATIC ${BLAKE3_SOURCES})
target_include_directories(blake3 PUBLIC third_party/blake3)
target_compile_definitions(blake3 PRIVATE
    BLAKE3_NO_AVX512
    BLAKE3_NO_AVX2
    BLAKE3_NO_SSE41
    BLAKE3_NO_SSE2
    BLAKE3_USE_NEON=0
)
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
