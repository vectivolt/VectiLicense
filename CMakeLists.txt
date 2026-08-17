# (c) 2026 VectiVolt — Apache-2.0 License
#
# Host build: the library (core/ plus transport/ if present) and the test
# suite. There is nothing platform-specific in here, and nothing that can sign
# — the minter is tools/vl_mint.py and it is not part of any build.
#
#   cmake -B build && cmake --build build && ctest --test-dir build --output-on-failure

cmake_minimum_required(VERSION 3.16)

project(VectiLicense
    VERSION 1.0.0
    DESCRIPTION "Offline, asymmetric device licensing. Verify-only on device."
    HOMEPAGE_URL "https://github.com/vectivolt/VectiLicense"
    LANGUAGES C)

option(VL_BUILD_TESTS "Build the VectiLicense test suite" ON)
option(VL_WERROR      "Treat warnings as errors"          ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# core/ is mandatory and self-contained. transport/ is optional framing help
# and may legitimately have been deleted from a checkout — hence GLOB rather
# than a list: a repo with no transport/ must still configure. CONFIGURE_DEPENDS
# so adding a file does not need a manual re-run of cmake.
file(GLOB VL_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/core/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/transport/*.c")

if(NOT VL_SOURCES)
    message(FATAL_ERROR "No sources found in core/ — is this a complete checkout?")
endif()

add_library(vectilicense STATIC ${VL_SOURCES})
add_library(VectiLicense::vectilicense ALIAS vectilicense)

target_include_directories(vectilicense
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/core)

# transport/ headers are part of the public surface when transport/ exists.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/transport")
    target_include_directories(vectilicense PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/transport>)
endif()

# HALs are not part of core and are never all compiled at once — each one is
# for exactly one platform. On a host, two of them apply: posix (real machine
# identity) and none (the documented stub). The cross-compiled HALs are not
# built here and are not claimed to build here.
set(VL_HOST_HALS "")
if(UNIX AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/hal/posix")
    list(APPEND VL_HOST_HALS posix)
endif()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/hal/none")
    list(APPEND VL_HOST_HALS none)
endif()
foreach(h IN LISTS VL_HOST_HALS)
    target_sources(vectilicense PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/hal/${h}/vl_hal_${h}.c")
    target_include_directories(vectilicense PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/hal/${h}>)
endforeach()

# The macOS half of hal/posix reads the hardware UUID out of the IO registry,
# which is the only reason this project links a framework at all.
if(APPLE AND "posix" IN_LIST VL_HOST_HALS)
    target_link_libraries(vectilicense PUBLIC "-framework IOKit" "-framework CoreFoundation")
endif()

# hal/none deliberately #warnings that it identifies nothing, which is right in
# firmware and wrong here: this build compiles it so the tests can exercise the
# stub, and -Werror would turn that reminder into a build failure.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/hal/none")
    set_source_files_properties("${CMAKE_CURRENT_SOURCE_DIR}/hal/none/vl_hal_none.c"
        PROPERTIES COMPILE_DEFINITIONS VL_HAL_NONE_ACKNOWLEDGED)
endif()

# The warning set the library is expected to survive. Kept on GNU/Clang only:
# forcing these onto an unknown vendor compiler turns a working build into a
# broken one for no benefit.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(vectilicense PRIVATE
        -Wall -Wextra -Wpedantic
        -Wshadow -Wstrict-prototypes -Wmissing-prototypes
        -Wconversion -Wsign-conversion -Wcast-qual -Wvla
        $<$<BOOL:${VL_WERROR}>:-Werror>)
endif()

# ---------------------------------------------------------------------------
# Tests. Each tests/test_*.c and tests/fuzz_*.c is its own executable with its
# own main(); each becomes a ctest case.
# ---------------------------------------------------------------------------
option(VL_SANITIZE_FUZZ "Build tests/fuzz_*.c with ASan + UBSan" ON)
# The library documents ASan+UBSan as its verification method, but instrumenting
# only fuzz_* means the other five tests link an uninstrumented archive — which
# is how a UB bug reachable from the RFC 8032 vectors sat in test_vl_core
# unnoticed. OFF by default because a sanitized fuzz soak is already the slow
# part of a plain `ctest`; turn it on for the documented run:
#   cmake -B build-asan -DVL_SANITIZE_ALL=ON && cmake --build build-asan && ctest --test-dir build-asan
option(VL_SANITIZE_ALL "Build EVERY test with ASan + UBSan, not just fuzz_*" OFF)

if(VL_BUILD_TESTS)
    enable_testing()

    set(VL_SAN_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all)
    if(VL_SANITIZE_FUZZ AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        include(CheckCCompilerFlag)
        set(CMAKE_REQUIRED_LINK_OPTIONS ${VL_SAN_FLAGS})
        check_c_compiler_flag("-fsanitize=address,undefined" VL_HAVE_SANITIZERS)
        unset(CMAKE_REQUIRED_LINK_OPTIONS)
        if(NOT VL_HAVE_SANITIZERS)
            message(STATUS "VectiLicense: no ASan/UBSan here — fuzz runs unsanitized")
        endif()
    endif()

    # Instrument the library itself rather than recompiling the sources into
    # each test: PUBLIC propagates both the compile and the link flags to
    # everything that links vectilicense, so all five non-fuzz tests exercise
    # instrumented core/ code with no per-target include-path surgery.
    if(VL_SANITIZE_ALL AND VL_HAVE_SANITIZERS)
        target_compile_options(vectilicense PUBLIC ${VL_SAN_FLAGS} -g)
        target_link_options(vectilicense PUBLIC ${VL_SAN_FLAGS})
    elseif(VL_SANITIZE_ALL)
        message(WARNING "VectiLicense: VL_SANITIZE_ALL=ON but no ASan/UBSan available")
    endif()

    file(GLOB VL_TEST_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_*.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz_*.c")

    foreach(src IN LISTS VL_TEST_SOURCES)
        get_filename_component(name ${src} NAME_WE)
        get_filename_component(ext ${src} EXT)
        if(ext STREQUAL ".cpp")
            enable_language(CXX)
            set_source_files_properties(${src} PROPERTIES CXX_STANDARD 11)
        endif()
        # The fuzz harness gets its own copy of the sources compiled WITH the
        # sanitizers, rather than linking the plain library: ASan and UBSan
        # only report on code they instrumented, and the code under test is
        # core/, not the harness. Without this the fuzz target still runs and
        # still proves there is no false accept — it just stops proving
        # anything about memory safety.
        if(name MATCHES "^fuzz_" AND VL_SANITIZE_FUZZ AND VL_HAVE_SANITIZERS)
            add_executable(${name} ${src} ${VL_SOURCES})
            target_include_directories(${name} PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/include)
            target_compile_options(${name} PRIVATE ${VL_SAN_FLAGS} -g)
            target_link_options(${name} PRIVATE ${VL_SAN_FLAGS})
        else()
            add_executable(${name} ${src})
            target_link_libraries(${name} PRIVATE vectilicense)
        endif()
        # Tests reach into core/ and bridge/ on purpose: they test the internal
        # primitives (SHA, base32, the Ed25519 verify) as well as the public API.
        target_include_directories(${name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/core
            ${CMAKE_CURRENT_SOURCE_DIR}/bridge
            ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${name} PRIVATE
                -Wall -Wextra $<$<BOOL:${VL_WERROR}>:-Werror>)
        endif()
        if(name MATCHES "^fuzz_")
            # Two seeds: a fuzz run pinned to one seed is a known-answer test
            # wearing a disguise. For a real soak: ./fuzz_vl_verify 500000 <seed>
            add_test(NAME ${name}       COMMAND ${name} 5000)
            add_test(NAME ${name}_seed2 COMMAND ${name} 5000 20260817)
            set_tests_properties(${name} ${name}_seed2 PROPERTIES TIMEOUT 600)
        else()
            add_test(NAME ${name} COMMAND ${name})
        endif()
    endforeach()
endif()

# ---------------------------------------------------------------------------
# Freestanding guard.
#
# "Runs anywhere, no OS, no heap, no libc" is the headline claim, and a host
# build cannot check it: every hosted toolchain has <string.h>, so a stray
# hosted #include stays green here and fails only on the customer's bench.
# <string.h> is NOT freestanding — C99 §4p6 lists exactly seven headers, and
# arm-none-eabi-gcc ships none of libc.
#
# -nostdinc drops the libc search path; -isystem <gcc's own include> puts back
# exactly the headers a freestanding implementation is required to provide.
# Compile-only: there is no libc to link against, which is the entire point.
# Silently skipped when no cross-compiler is installed.
# ---------------------------------------------------------------------------
find_program(VL_ARM_GCC arm-none-eabi-gcc)
if(VL_BUILD_TESTS AND VL_ARM_GCC)
    execute_process(COMMAND ${VL_ARM_GCC} -print-file-name=include
                    OUTPUT_VARIABLE VL_ARM_GCC_INC
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    foreach(cpu cortex-m4 cortex-m0plus)
        set(d "${CMAKE_CURRENT_BINARY_DIR}/freestanding-${cpu}")
        file(MAKE_DIRECTORY "${d}")
        add_test(NAME freestanding_${cpu}
            COMMAND ${VL_ARM_GCC}
                -std=c99 -mcpu=${cpu} -mthumb -Os -ffreestanding
                -nostdinc -isystem ${VL_ARM_GCC_INC}
                -Wall -Wextra -Werror -Wpedantic
                -Wshadow -Wstrict-prototypes -Wmissing-prototypes
                -Wconversion -Wsign-conversion -Wcast-qual -Wvla
                -I${CMAKE_CURRENT_SOURCE_DIR}/include
                -I${CMAKE_CURRENT_SOURCE_DIR}/core
                -I${CMAKE_CURRENT_SOURCE_DIR}/transport
                -c ${VL_SOURCES}
            WORKING_DIRECTORY "${d}")
    endforeach()
else()
    message(STATUS "VectiLicense: no arm-none-eabi-gcc — freestanding check skipped")
endif()

# ---------------------------------------------------------------------------
install(TARGETS vectilicense EXPORT vectilicense-targets ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
