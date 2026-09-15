set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
cmake_minimum_required(VERSION 3.24)
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()
if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
endif()
if(POLICY CMP0169)
    cmake_policy(SET CMP0169 OLD)
endif()
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "Embedded")

if(NOT DEFINED MEMCACHED_VERSION)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/version.num")
        file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/version.num" FILE_VERSION LIMIT_COUNT 1)
        string(STRIP "${FILE_VERSION}" FILE_VERSION)
        if(FILE_VERSION MATCHES "^[0-9]")
            set(MEMCACHED_VERSION "${FILE_VERSION}")
        endif()
    endif()
endif()

if(NOT DEFINED MEMCACHED_VERSION OR "${MEMCACHED_VERSION}" STREQUAL "")
    set(MEMCACHED_VERSION "1.6.45")
endif()

# Clean version for CMake project() command (numeric: X.Y.Z)
string(REGEX MATCH "^([0-9]+\\.[0-9]+(\\.[0-9]+)?)" CMAKE_PROJ_VER "${MEMCACHED_VERSION}")
if(NOT CMAKE_PROJ_VER)
    set(CMAKE_PROJ_VER "1.6.45")
endif()

project(memcached VERSION ${CMAKE_PROJ_VER} LANGUAGES C)

if(MSVC)
    string(REPLACE "/Zi" "/Z7" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
    string(REPLACE "/Zi" "/Z7" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(APPLE)
    add_compile_definitions(_DARWIN_C_SOURCE=1)
elseif(UNIX)
    add_compile_definitions(_GNU_SOURCE=1)
endif()

# User configurable options
option(ENABLE_EXTSTORE "Enable external storage engine" ON)
option(ENABLE_TLS "Enable TLS support via OpenSSL" OFF)
option(ENABLE_SASL "Enable SASL authentication" OFF)
option(ENABLE_PROXY "Enable proxy functionality with Lua" OFF)
option(BUILD_TESTING "Build test executables" ON)

# Dependency management via FetchContent
include(FetchContent)

# 1. auto-win-msvc compatibility layer
if(WIN32 OR MSVC)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../auto-win-msvc/CMakeLists.txt")
        if(NOT DEFINED FETCHCONTENT_SOURCE_DIR_AUTO-WIN-MSVC)
            set(FETCHCONTENT_SOURCE_DIR_AUTO-WIN-MSVC "${CMAKE_CURRENT_SOURCE_DIR}/../auto-win-msvc" CACHE PATH "Local auto-win-msvc source dir")
        endif()
        if(NOT DEFINED FETCHCONTENT_SOURCE_DIR_AUTO_WIN_MSVC)
            set(FETCHCONTENT_SOURCE_DIR_AUTO_WIN_MSVC "${CMAKE_CURRENT_SOURCE_DIR}/../auto-win-msvc" CACHE PATH "Local auto-win-msvc source dir")
        endif()
    endif()

    set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static libraries" FORCE)
    set(AUTO_WIN_MSVC_BUILD_TESTING OFF CACHE BOOL "Disable auto-win-msvc tests" FORCE)

    FetchContent_Declare(
        auto-win-msvc
        GIT_REPOSITORY https://github.com/SamuelMarks/auto-win-msvc.git
        GIT_TAG master
    )
    FetchContent_GetProperties(auto-win-msvc)
    if(NOT auto-win-msvc_POPULATED)
        FetchContent_Populate(auto-win-msvc)
    endif()

    if(EXISTS "${auto-win-msvc_SOURCE_DIR}/linux-epoll" AND NOT EXISTS "${auto-win-msvc_SOURCE_DIR}/linux-epoll/patch_wepoll.cmake")
        file(WRITE "${auto-win-msvc_SOURCE_DIR}/linux-epoll/patch_wepoll.cmake"
"if(DEFINED WEPOLL_SOURCE_DIR AND EXISTS \"\${WEPOLL_SOURCE_DIR}/wepoll.c\")
    set(_wepoll_file \"\${WEPOLL_SOURCE_DIR}/wepoll.c\")
elseif(EXISTS \"\${CMAKE_CURRENT_LIST_DIR}/wepoll.c\")
    set(_wepoll_file \"\${CMAKE_CURRENT_LIST_DIR}/wepoll.c\")
elseif(EXISTS \"wepoll.c\")
    set(_wepoll_file \"wepoll.c\")
endif()

if(DEFINED _wepoll_file AND EXISTS \"\${_wepoll_file}\")
    file(READ \"\${_wepoll_file}\" _content)
    string(REPLACE \"typedef void* nt__fn_ptr_cast_t;\" \"typedef void (*nt__fn_ptr_cast_t)(void);\" _content \"\${_content}\")
    string(REPLACE \"typedef struct tree {\" \"struct tree {\" _content \"\${_content}\")
    string(REPLACE \"typedef struct tree_node {\" \"struct tree_node {\" _content \"\${_content}\")
    string(REPLACE \"typedef struct ts_tree_node {\" \"struct ts_tree_node {\" _content \"\${_content}\")
    string(REPLACE \"typedef struct queue_node {\" \"struct queue_node {\" _content \"\${_content}\")
    string(REPLACE \"typedef struct queue {\" \"struct queue {\" _content \"\${_content}\")
    string(REPLACE \"typedef struct poll_group {\" \"struct poll_group {\" _content \"\${_content}\")
    string(REPLACE \"typedef struct port_state {\" \"struct port_state {\" _content \"\${_content}\")
    string(REPLACE \"typedef struct sock_state {\" \"struct sock_state {\" _content \"\${_content}\")
    string(REPLACE \"} tree_t;\" \"};\" _content \"\${_content}\")
    string(REPLACE \"} tree_node_t;\" \"};\" _content \"\${_content}\")
    string(REPLACE \"} ts_tree_node_t;\" \"};\" _content \"\${_content}\")
    string(REPLACE \"} queue_node_t;\" \"};\" _content \"\${_content}\")
    string(REPLACE \"} queue_t;\" \"};\" _content \"\${_content}\")
    string(REPLACE \"} poll_group_t;\" \"};\" _content \"\${_content}\")
    string(REPLACE \"} port_state_t;\" \"};\" _content \"\${_content}\")
    string(REPLACE \"} sock_state_t;\" \"};\" _content \"\${_content}\")
    file(WRITE \"\${_wepoll_file}\" \"\${_content}\")
endif()
")
    endif()

    if(NOT TARGET auto-win-msvc)
        add_subdirectory(${auto-win-msvc_SOURCE_DIR} ${auto-win-msvc_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()
else()
    add_library(auto-win-msvc INTERFACE)
endif()

# 2. Libevent 2.x
set(EVENT__DISABLE_TESTS ON CACHE BOOL "" FORCE)
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "" FORCE)
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "" FORCE)
set(EVENT__MSVC_STATIC_RUNTIME OFF CACHE BOOL "" FORCE)
if(NOT ENABLE_TLS)
    set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "" FORCE)
endif()
set(EVENT__BUILD_SHARED_LIBRARIES OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    libevent
    GIT_REPOSITORY https://github.com/libevent/libevent.git
    GIT_TAG release-2.1.12-stable
)

FetchContent_GetProperties(libevent)
if(NOT libevent_POPULATED)
    FetchContent_Populate(libevent)
    add_subdirectory(${libevent_SOURCE_DIR} ${libevent_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

if(NOT TARGET libevent::core)
    if(TARGET event_core_static)
        add_library(libevent::core ALIAS event_core_static)
    elseif(TARGET event_core)
        add_library(libevent::core ALIAS event_core)
    endif()
endif()

if(NOT TARGET libevent::extra)
    if(TARGET event_extra_static)
        add_library(libevent::extra ALIAS event_extra_static)
    elseif(TARGET event_extra)
        add_library(libevent::extra ALIAS event_extra)
    endif()
endif()

#Generate config.h
set(CONFIG_H_CONTENT [=[/* Generated by CMake for memcached */
#ifndef CONFIG_H
#define CONFIG_H

#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if defined(__APPLE__)
#include <sys/param.h>
#endif

#define PACKAGE "memcached"
#define PACKAGE_NAME "memcached"
#define PACKAGE_VERSION "@MEMCACHED_VERSION@"
#define VERSION "@MEMCACHED_VERSION@"
#define HAVE_LIBEVENT_NEW 1
#if defined(_WIN32) || defined(_MSC_VER) || defined(__APPLE__)
#define HAVE_HTONLL 1
#endif
#define NEED_ALIGN 1
#define SIZEOF_VOID_P ]=])

string(APPEND CONFIG_H_CONTENT "${CMAKE_SIZEOF_VOID_P}
")
string(APPEND CONFIG_H_CONTENT [=[#define DISABLE_UNIX_SOCKET 1
#define ENDIAN_LITTLE 1
#define IOV_MAX 1024
#define MAXPATHLEN 4096
#define HAVE_GETOPT_LONG 1
#define HAVE_INTTYPES_H 1
#define HAVE_SIGACTION 1
#define HAVE_PTHREAD_SETNAME_NP 1
#define HAVE_STDBOOL_H 1
#define HAVE_STDINT_H 1

#include <stdbool.h>
#include <stdint.h>
]=])

if(ENABLE_EXTSTORE)
    string(APPEND CONFIG_H_CONTENT "
#define EXTSTORE 1
")
endif()

if(ENABLE_TLS)
    string(APPEND CONFIG_H_CONTENT "
#define TLS 1
")
endif()

if(ENABLE_SASL)
    string(APPEND CONFIG_H_CONTENT "
#define ENABLE_SASL 1
")
endif()

if(ENABLE_PROXY)
    string(APPEND CONFIG_H_CONTENT "
#define PROXY 1
")
endif()

string(APPEND CONFIG_H_CONTENT "
#endif /* CONFIG_H */
")
string(CONFIGURE "${CONFIG_H_CONTENT}" CONFIG_H_CONTENT @ONLY)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/config.h" "${CONFIG_H_CONTENT}")

# Common source lists
set(MEMCACHED_CORE_SOURCES
    memcached.c
    proto_bin.c
    util.c
    proto_parser.c
    thread.c
    hash.c
    jenkins_hash.c
    murmur3_hash.c
    slabs.c
    items.c
    assoc.c
    daemon.c
    stats_prefix.c
    cache.c
    bipbuffer.c
    base64.c
    logger.c
    crawler.c
    itoa_ljust.c
    slab_automove.c
    slabs_mover.c
    authfile.c
    restart.c
    proto_text.c
    vendor/mcmc/mcmc.c
)

if(ENABLE_EXTSTORE)
    list(APPEND MEMCACHED_CORE_SOURCES
        extstore.c
        crc32c.c
        storage.c
        slab_automove_extstore.c
    )
endif()

if(ENABLE_TLS)
    list(APPEND MEMCACHED_CORE_SOURCES tls.c)
endif()

if(ENABLE_SASL)
    list(APPEND MEMCACHED_CORE_SOURCES sasl_defs.c)
endif()

# Define memcached executable
add_executable(memcached ${MEMCACHED_CORE_SOURCES})

target_include_directories(memcached PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/vendor/mcmc"
)

target_compile_definitions(memcached PRIVATE
    HAVE_CONFIG_H
)

if(MSVC)
    target_compile_options(memcached PRIVATE
        /W3
        /D_CRT_SECURE_NO_WARNINGS
        /D_CRT_NONSTDC_NO_DEPRECATE
        /FIwin_compat.h
    )
else()
    target_compile_options(memcached PRIVATE -Wall -pthread)
endif()

target_link_libraries(memcached PRIVATE
    auto-win-msvc
    libevent::core
    libevent::extra
)

if(WIN32 OR MSVC)
    target_link_libraries(memcached PRIVATE
        ws2_32
        dbghelp
        advapi32
        userenv
        ole32
        psapi
        bcrypt
    )
    if(EXISTS "${libevent_BINARY_DIR}/bin" OR TARGET event_core OR TARGET event_core_shared)
        add_custom_command(TARGET memcached POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${libevent_BINARY_DIR}/bin"
                "${CMAKE_CURRENT_BINARY_DIR}"
        )
    endif()
endif()

if(CMAKE_CROSSCOMPILING_EMULATOR)
    set_target_properties(memcached PROPERTIES CROSSCOMPILING_EMULATOR "${CMAKE_CROSSCOMPILING_EMULATOR}")
elseif(MSVC AND NOT WIN32)
    set_target_properties(memcached PROPERTIES CROSSCOMPILING_EMULATOR "wine")
endif()

# Test and helper targets
if(BUILD_TESTING)
    enable_testing()

    # Target: sizes
    add_executable(sizes sizes.c)
    target_include_directories(sizes PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_definitions(sizes PRIVATE HAVE_CONFIG_H)
    if(MSVC)
        target_compile_options(sizes PRIVATE /W3 /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_DEPRECATE /FIwin_compat.h)
    endif()
    target_link_libraries(sizes PRIVATE auto-win-msvc libevent::core libevent::extra)
    if(WIN32 OR MSVC)
        target_link_libraries(sizes PRIVATE ws2_32 dbghelp advapi32 userenv ole32 psapi bcrypt)
    endif()
    if(CMAKE_CROSSCOMPILING_EMULATOR)
        set_target_properties(sizes PROPERTIES CROSSCOMPILING_EMULATOR "${CMAKE_CROSSCOMPILING_EMULATOR}")
    elseif(MSVC AND NOT WIN32)
        set_target_properties(sizes PROPERTIES CROSSCOMPILING_EMULATOR "wine")
    endif()
    add_test(NAME sizes COMMAND sizes)
    set_tests_properties(sizes PROPERTIES
        ENVIRONMENT "WINEDEBUG=-all;MVK_CONFIG_LOG_LEVEL=0"
    )

    # Target: testapp
    set(TESTAPP_SOURCES
        testapp.c
        util.c
        stats_prefix.c
        jenkins_hash.c
        murmur3_hash.c
        cache.c
        crc32c.c
    )
    add_executable(testapp ${TESTAPP_SOURCES})
    target_include_directories(testapp PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_definitions(testapp PRIVATE HAVE_CONFIG_H)
    if(MSVC)
        target_compile_options(testapp PRIVATE /W3 /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_DEPRECATE /FIwin_compat.h /UNDEBUG)
    else()
        target_compile_options(testapp PRIVATE -UNDEBUG)
    endif()
    target_link_libraries(testapp PRIVATE auto-win-msvc libevent::core libevent::extra)
    if(WIN32 OR MSVC)
        target_link_libraries(testapp PRIVATE ws2_32 dbghelp advapi32 userenv ole32 psapi bcrypt)
    endif()
    if(CMAKE_CROSSCOMPILING_EMULATOR)
        set_target_properties(testapp PROPERTIES CROSSCOMPILING_EMULATOR "${CMAKE_CROSSCOMPILING_EMULATOR}")
    elseif(MSVC AND NOT WIN32)
        set_target_properties(testapp PROPERTIES CROSSCOMPILING_EMULATOR "wine")
    endif()
    add_test(NAME testapp COMMAND testapp)
    set_tests_properties(testapp PROPERTIES
        ENVIRONMENT "WINEDEBUG=-all;MVK_CONFIG_LOG_LEVEL=0"
    )

    # Target: timedrun
    add_executable(timedrun timedrun.c)
    target_include_directories(timedrun PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_definitions(timedrun PRIVATE HAVE_CONFIG_H)
    if(MSVC)
        target_compile_options(timedrun PRIVATE /W3 /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_DEPRECATE /FIwin_compat.h)
    endif()
    target_link_libraries(timedrun PRIVATE auto-win-msvc libevent::core libevent::extra)
    if(WIN32 OR MSVC)
        target_link_libraries(timedrun PRIVATE ws2_32 dbghelp advapi32 userenv ole32 psapi bcrypt)
    endif()
    if(CMAKE_CROSSCOMPILING_EMULATOR)
        set_target_properties(timedrun PROPERTIES CROSSCOMPILING_EMULATOR "${CMAKE_CROSSCOMPILING_EMULATOR}")
    elseif(MSVC AND NOT WIN32)
        set_target_properties(timedrun PROPERTIES CROSSCOMPILING_EMULATOR "wine")
    endif()

    # Cross-platform C89 Test Suite integrated into CTest
    set(C_TEST_SOURCES
        tests/c_harness.c
        tests/c_test_runner.c
        tests/test_startup.c
        tests/test_basic.c
        tests/test_getset.c
        tests/test_flags.c
        tests/test_cas.c
        tests/test_touch.c
        tests/test_incrdecr.c
        tests/test_expirations.c
        tests/test_flush_all.c
        tests/test_stats.c
        tests/test_bogus.c
        tests/test_quit.c
        tests/test_multiversioning.c
        tests/test_binary.c
        tests/test_limits.c
        tests/test_metaget.c
        tests/test_dyn_maxbytes.c
        tests/test_slabs.c
    )
    add_executable(c_test_runner ${C_TEST_SOURCES})
    target_include_directories(c_test_runner PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    target_compile_definitions(c_test_runner PRIVATE HAVE_CONFIG_H)
    if(MSVC)
        target_compile_options(c_test_runner PRIVATE /W3 /D_CRT_SECURE_NO_WARNINGS /D_CRT_NONSTDC_NO_DEPRECATE /FIwin_compat.h)
    endif()
    target_link_libraries(c_test_runner PRIVATE auto-win-msvc libevent::core libevent::extra)
    if(WIN32 OR MSVC)
        target_link_libraries(c_test_runner PRIVATE ws2_32 dbghelp advapi32 userenv ole32 psapi bcrypt)
    endif()
    if(CMAKE_CROSSCOMPILING_EMULATOR)
        set_target_properties(c_test_runner PROPERTIES CROSSCOMPILING_EMULATOR "${CMAKE_CROSSCOMPILING_EMULATOR}")
    elseif(MSVC AND NOT WIN32)
        set_target_properties(c_test_runner PROPERTIES CROSSCOMPILING_EMULATOR "wine")
    endif()

    set(C_TEST_ENV
        "MEMCACHED_BIN=$<TARGET_FILE:memcached>"
    )
    if(CMAKE_CROSSCOMPILING_EMULATOR)
        list(APPEND C_TEST_ENV "MEMCACHED_EMULATOR=${CMAKE_CROSSCOMPILING_EMULATOR}")
    elseif(MSVC AND NOT WIN32)
        list(APPEND C_TEST_ENV "MEMCACHED_EMULATOR=wine")
    endif()

    set(C_TEST_MODULES
        test_startup
        test_basic
        test_getset
        test_flags
        test_cas
        test_touch
        test_incrdecr
        test_expirations
        test_flush_all
        test_stats
        test_bogus
        test_quit
        test_multiversioning
        test_binary
        test_limits
        test_metaget
        test_dyn_maxbytes
        test_slabs
    )

    foreach(MODULE ${C_TEST_MODULES})
        add_test(
            NAME "c_${MODULE}"
            COMMAND c_test_runner "${MODULE}"
        )
        set_tests_properties("c_${MODULE}" PROPERTIES
            ENVIRONMENT "${C_TEST_ENV}"
            WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        )
    endforeach()

    add_test(
        NAME "c_all"
        COMMAND c_test_runner "all"
    )
    set_tests_properties("c_all" PROPERTIES
        ENVIRONMENT "${C_TEST_ENV}"
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )

    # Cross-platform Python Test Suite integrated into CTest
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_FOUND)
        set(TEST_MODULES
            test_startup
            test_basic
            test_getset
            test_flags
            test_cas
            test_touch
            test_incrdecr
            test_expirations
            test_flush_all
            test_stats
            test_bogus
            test_quit
            test_multiversioning
            test_binary
            test_limits
            test_metaget
            test_dyn_maxbytes
            test_slabs
        )

        set(PY_TEST_ENV
            "MEMCACHED_BIN=$<TARGET_FILE:memcached>"
        )
        if(CMAKE_CROSSCOMPILING_EMULATOR)
            list(APPEND PY_TEST_ENV "MEMCACHED_EMULATOR=${CMAKE_CROSSCOMPILING_EMULATOR}")
        elseif(MSVC AND NOT WIN32)
            list(APPEND PY_TEST_ENV "MEMCACHED_EMULATOR=wine")
        endif()

        foreach(MODULE ${TEST_MODULES})
            add_test(
                NAME "py_${MODULE}"
                COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/${MODULE}.py"
            )
            set_tests_properties("py_${MODULE}" PROPERTIES
                ENVIRONMENT "${PY_TEST_ENV}"
                WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
            )
        endforeach()

        add_test(
            NAME "py_all"
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.py"
        )
        set_tests_properties("py_all" PROPERTIES
            ENVIRONMENT "${PY_TEST_ENV}"
            WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
        )
    endif()
endif()

# ==============================================================================
# Installation & CPack Packaging
# ==============================================================================
install(TARGETS memcached
    RUNTIME DESTINATION bin
    COMPONENT memcached
)

if(WIN32)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/memcached-service.exe")
        install(PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/memcached-service.exe" DESTINATION bin COMPONENT memcached)
    elseif(EXISTS "${CMAKE_BINARY_DIR}/memcached-service.exe")
        install(PROGRAMS "${CMAKE_BINARY_DIR}/memcached-service.exe" DESTINATION bin COMPONENT memcached)
    endif()
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/memcached-service.xml")
        install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/memcached-service.xml" DESTINATION bin COMPONENT memcached)
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/packaging/memcached-service.xml")
        install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/packaging/memcached-service.xml" DESTINATION bin COMPONENT memcached)
    endif()
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/COPYING" DESTINATION . COMPONENT memcached RENAME "COPYING.txt")
endif()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/README.md" DESTINATION . COMPONENT memcached)
endif()

set(CPACK_PACKAGE_NAME "Memcached")
set(CPACK_PACKAGE_VENDOR "Memcached")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "High-performance, distributed memory object caching system.")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://memcached.org")
set(CPACK_PACKAGE_CONTACT "Samuel Marks <807580+SamuelMarks@users.noreply.github.com>")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/COPYING")
set(CPACK_PACKAGE_VERSION "${MEMCACHED_VERSION}")
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "Memcached")
set(CPACK_PACKAGE_FILE_NAME "Memcached-${MEMCACHED_VERSION}-win64")

if(WIN32)
    set(CPACK_GENERATOR "ZIP;WIX;NSIS")

    # WiX generator settings
    set(CPACK_WIX_UPGRADE_GUID "D62E10B3-5A38-4FBE-8628-9844F4BC8E01")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/packaging/wix_patch.xml")
        set(CPACK_WIX_PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/packaging/wix_patch.xml")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/wix_patch.xml")
        set(CPACK_WIX_PATCH_FILE "${CMAKE_CURRENT_SOURCE_DIR}/wix_patch.xml")
    endif()

    # NSIS generator settings
    set(CPACK_NSIS_DISPLAY_NAME "Memcached ${PROJECT_VERSION}")
    set(CPACK_NSIS_PACKAGE_NAME "Memcached")
    set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS "ExecWait '$\\\"$INSTDIR\\\\bin\\\\memcached-service.exe$\\\" install'\nExecWait '$\\\"$INSTDIR\\\\bin\\\\memcached-service.exe$\\\" start'")
    set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "ExecWait '$\\\"$INSTDIR\\\\bin\\\\memcached-service.exe$\\\" stop'\nExecWait '$\\\"$INSTDIR\\\\bin\\\\memcached-service.exe$\\\" uninstall'")
else()
    set(CPACK_GENERATOR "TGZ;ZIP")
endif()

include(CPack)

