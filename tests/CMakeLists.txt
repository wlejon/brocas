function(brocas_test name)
    cmake_parse_arguments(T "" "TIMEOUT" "SOURCES;LIBS" ${ARGN})
    add_executable(${name} ${T_SOURCES})
    target_link_libraries(${name} PRIVATE brocas ${T_LIBS})
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/src
    )
    brocas_warnings(${name})
    target_compile_definitions(${name} PRIVATE BROCAS_TEST_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
    if(WIN32)
        target_compile_definitions(${name} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
    endif()
    if(NOT T_TIMEOUT)
        set(T_TIMEOUT 60)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES TIMEOUT ${T_TIMEOUT})
endfunction()

brocas_test(test_hash SOURCES test_hash.cpp)
brocas_test(test_fastcdc SOURCES test_fastcdc.cpp)
brocas_test(test_store SOURCES test_store.cpp)
brocas_test(test_manifest SOURCES test_manifest.cpp)
brocas_test(test_sync SOURCES test_sync.cpp)
brocas_test(test_sync_process SOURCES test_sync_process.cpp)
brocas_test(test_fuzz SOURCES test_fuzz.cpp)
