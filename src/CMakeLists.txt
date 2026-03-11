add_executable(multiplexd
    util.c util.h
    conf.c conf.h
    jsonutil.c jsonutil.h
    tlsutil.c tlsutil.h
    gencerts.c gencerts.h
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    main.c
)

target_include_directories(multiplexd PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(multiplexd PRIVATE csnippets)

if(FORCE_POSIX)
    target_compile_definitions(multiplexd PRIVATE _POSIX_C_SOURCE=200809L)
else()
    target_compile_definitions(multiplexd PRIVATE _GNU_SOURCE)
endif()

include(CheckSymbolExists)
check_symbol_exists(TCP_FASTOPEN "netinet/tcp.h" HAVE_TCP_FASTOPEN)
check_symbol_exists(TCP_NOTSENT_LOWAT "netinet/tcp.h" HAVE_TCP_NOTSENT_LOWAT)
check_symbol_exists(TCP_USER_TIMEOUT "netinet/tcp.h" HAVE_TCP_USER_TIMEOUT)

if(NOT FORCE_POSIX)
    if(HAVE_TCP_FASTOPEN)
        set(WITH_TCP_FASTOPEN TRUE)
    endif()
    if(HAVE_TCP_NOTSENT_LOWAT)
        set(WITH_TCP_NOTSENT_LOWAT TRUE)
    endif()
    if(HAVE_TCP_USER_TIMEOUT)
        set(WITH_TCP_USER_TIMEOUT TRUE)
    endif()
endif()

target_compile_options(multiplexd PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/config.h")
target_compile_options(multiplexd PRIVATE -pedantic -Wall -Wextra -Werror)

if(LIBM)
    target_link_libraries(multiplexd PRIVATE m)
endif()

if(WITH_THREADS)
    target_link_libraries(multiplexd PRIVATE Threads::Threads)
endif()

# find libev
find_path(LIBEV_INCLUDE_DIR NAMES ev.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(LIBEV_LIBRARY NAMES libev.a)
else()
    find_library(LIBEV_LIBRARY NAMES ev)
endif()
if(EXISTS "${LIBEV_INCLUDE_DIR}/ev.h")
    file(READ "${LIBEV_INCLUDE_DIR}/ev.h" LIBEV_VERSION_STR)
    string(REGEX MATCH "#define EV_VERSION_MAJOR[ \t]+([0-9]+)" _ ${LIBEV_VERSION_STR})
    set(EV_VERSION_MAJOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "#define EV_VERSION_MINOR[ \t]+([0-9]+)" _ ${LIBEV_VERSION_STR})
    set(EV_VERSION_MINOR ${CMAKE_MATCH_1})
    set(LIBEV_VERSION "${EV_VERSION_MAJOR}.${EV_VERSION_MINOR}")
endif()
if((NOT ${LIBEV_VERSION} VERSION_GREATER_EQUAL "4.31") OR (NOT EXISTS ${LIBEV_LIBRARY}))
    message(FATAL_ERROR "libev (>= 4.31) not found")
endif()
message(STATUS "libev ${LIBEV_VERSION}: ${LIBEV_LIBRARY}")
target_include_directories(multiplexd SYSTEM PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(multiplexd PRIVATE ${LIBEV_LIBRARY})

# find OpenSSL
if(ENABLE_TLS)
    if(BUILD_STATIC OR LINK_STATIC_LIBS)
        set(OPENSSL_USE_STATIC_LIBS TRUE)
    endif()
    find_package(OpenSSL 3.0)
    if(OpenSSL_FOUND)
        message(STATUS "OpenSSL ${OPENSSL_VERSION}: ${OPENSSL_LIBRARIES}")
        target_include_directories(multiplexd SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_link_libraries(multiplexd PRIVATE OpenSSL::SSL OpenSSL::Crypto)
        set(WITH_TLS TRUE)
    endif()
endif()

# find json-c
find_path(JSONC_INCLUDE_DIR NAMES json-c/json.h)
if(BUILD_STATIC OR LINK_STATIC_LIBS)
    find_library(JSONC_LIBRARY NAMES libjson-c.a)
else()
    find_library(JSONC_LIBRARY NAMES json-c)
endif()
if((NOT EXISTS "${JSONC_INCLUDE_DIR}/json-c/json.h") OR (NOT EXISTS ${JSONC_LIBRARY}))
    message(FATAL_ERROR "json-c not found")
endif()
message(STATUS "json-c: ${JSONC_LIBRARY}")
target_include_directories(multiplexd SYSTEM PRIVATE ${JSONC_INCLUDE_DIR})
target_link_libraries(multiplexd PRIVATE ${JSONC_LIBRARY})

install(TARGETS multiplexd DESTINATION bin)

# generate config.h
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    @ONLY)

# generate version.c
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/version.c.in"
    "${CMAKE_CURRENT_BINARY_DIR}/version.c"
    ESCAPE_QUOTES)

target_sources(multiplexd
    PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    "${CMAKE_CURRENT_BINARY_DIR}/version.c"
)

add_subdirectory(mux)

# =============================================================================
# Tests
# =============================================================================

# Write an LSAN suppression file for json-c internal allocations.
file(WRITE "${CMAKE_BINARY_DIR}/lsan.supp"
    "# json-c internal global allocations (gettext/locale argz state).\n"
    "leak:__argz_add_sep\n"
    "leak:json_c_get_locale_info\n"
)

function(add_src_test target_name)
    add_executable(${target_name} ${ARGN})

    target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_include_directories(${target_name} PRIVATE ${CMAKE_SOURCE_DIR}/contrib/csnippets)

    target_compile_options(${target_name} PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/config.h")
    target_compile_options(${target_name} PRIVATE -pedantic -Wall -Wextra -Werror)

    if(FORCE_POSIX)
        target_compile_definitions(${target_name} PRIVATE _POSIX_C_SOURCE=200809L)
    else()
        target_compile_definitions(${target_name} PRIVATE _GNU_SOURCE)
    endif()

    target_include_directories(${target_name} SYSTEM PRIVATE ${LIBEV_INCLUDE_DIR})
    target_link_libraries(${target_name} PRIVATE ${LIBEV_LIBRARY})

    if(WITH_TLS)
        target_include_directories(${target_name} SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})
        target_link_libraries(${target_name} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()

    target_include_directories(${target_name} SYSTEM PRIVATE ${JSONC_INCLUDE_DIR})
    target_link_libraries(${target_name} PRIVATE ${JSONC_LIBRARY})

    if(LIBM)
        target_link_libraries(${target_name} PRIVATE m)
    endif()

    target_link_libraries(${target_name} PRIVATE csnippets)
    if(Threads_FOUND)
        target_link_libraries(${target_name} PRIVATE Threads::Threads)
    endif()

    target_sources(${target_name}
        PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/config.h"
        "${CMAKE_CURRENT_BINARY_DIR}/version.c"
    )

    add_test(NAME ${target_name} COMMAND ${target_name})
    set_tests_properties(${target_name} PROPERTIES
        ENVIRONMENT "LSAN_OPTIONS=suppressions=${CMAKE_BINARY_DIR}/lsan.supp"
    )
    add_dependencies(check ${target_name})
endfunction()

# JSON utility unit tests
add_src_test(jsonutil_test
    jsonutil.c jsonutil.h
    jsonutil_test.c
)

# Configuration parser unit tests
add_src_test(conf_test
    jsonutil.c jsonutil.h
    conf.c conf.h
    conf_test.c
)

# Utility function unit tests
add_src_test(util_test
    util.c util.h
    util_test.c
)

# Listener unit tests
add_src_test(listener_test
    util.c util.h
    listener.c listener.h
    listener_test.c
)

# Certificate generation tests (always registered; no-op when TLS disabled)
add_src_test(gencerts_test
    gencerts.c gencerts.h
    tlsutil.c tlsutil.h
    gencerts_test.c
)

# TLS context unit tests (always registered; no-op when TLS disabled)
add_src_test(tlsutil_test
    gencerts.c gencerts.h
    tlsutil.c tlsutil.h
    tlsutil_test.c
)

# Tunnel unit tests
add_src_test(tunnel_test
    util.c util.h
    conf.c conf.h
    jsonutil.c jsonutil.h
    tlsutil.c tlsutil.h
    gencerts.c gencerts.h
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    mux/dispatch.c mux/dispatch.h
    mux/estimator.c mux/estimator.h
    mux/handshake.c mux/handshake.h
    mux/mux.c mux/mux.h
    mux/frame.c mux/frame.h
    mux/sched.c mux/sched.h
    mux/session.c mux/session.h
    mux/stream.c mux/stream.h
    mux/wire.c mux/wire.h
    tunnel_test.c
)

# Server unit tests
add_executable(server_test
    util.c util.h
    conf.c conf.h
    jsonutil.c jsonutil.h
    tlsutil.c tlsutil.h
    gencerts.c gencerts.h
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    mux/dispatch.c mux/dispatch.h
    mux/estimator.c mux/estimator.h
    mux/handshake.c mux/handshake.h
    mux/mux.c mux/mux.h
    mux/frame.c mux/frame.h
    mux/sched.c mux/sched.h
    mux/session.c mux/session.h
    mux/stream.c mux/stream.h
    mux/wire.c mux/wire.h
    server_test.c
)

target_include_directories(server_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(server_test PRIVATE ${CMAKE_SOURCE_DIR}/contrib/csnippets)

target_compile_options(server_test PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/config.h")
target_compile_options(server_test PRIVATE -pedantic -Wall -Wextra -Werror)

if(FORCE_POSIX)
    target_compile_definitions(server_test PRIVATE _POSIX_C_SOURCE=200809L)
else()
    target_compile_definitions(server_test PRIVATE _GNU_SOURCE)
endif()

target_include_directories(server_test SYSTEM PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(server_test PRIVATE ${LIBEV_LIBRARY})

if(WITH_TLS)
    target_include_directories(server_test SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(server_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

target_include_directories(server_test SYSTEM PRIVATE ${JSONC_INCLUDE_DIR})
target_link_libraries(server_test PRIVATE ${JSONC_LIBRARY})

if(LIBM)
    target_link_libraries(server_test PRIVATE m)
endif()

target_link_libraries(server_test PRIVATE csnippets)
if(Threads_FOUND)
    target_link_libraries(server_test PRIVATE Threads::Threads)
endif()

target_sources(server_test
    PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    "${CMAKE_CURRENT_BINARY_DIR}/version.c"
)

add_test(NAME server_test COMMAND server_test)
add_dependencies(check server_test)

# API server unit tests
add_executable(api_server_test
    util.c util.h
    conf.c conf.h
    jsonutil.c jsonutil.h
    tlsutil.c tlsutil.h
    gencerts.c gencerts.h
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    mux/dispatch.c mux/dispatch.h
    mux/estimator.c mux/estimator.h
    mux/handshake.c mux/handshake.h
    mux/mux.c mux/mux.h
    mux/frame.c mux/frame.h
    mux/sched.c mux/sched.h
    mux/session.c mux/session.h
    mux/stream.c mux/stream.h
    mux/wire.c mux/wire.h
    api_server_test.c
)

target_include_directories(api_server_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(api_server_test PRIVATE ${CMAKE_SOURCE_DIR}/contrib/csnippets)

target_compile_options(api_server_test PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/config.h")
target_compile_options(api_server_test PRIVATE -pedantic -Wall -Wextra -Werror)

if(FORCE_POSIX)
    target_compile_definitions(api_server_test PRIVATE _POSIX_C_SOURCE=200809L)
else()
    target_compile_definitions(api_server_test PRIVATE _GNU_SOURCE)
endif()

target_include_directories(api_server_test SYSTEM PRIVATE ${LIBEV_INCLUDE_DIR})
target_link_libraries(api_server_test PRIVATE ${LIBEV_LIBRARY})

if(WITH_TLS)
    target_include_directories(api_server_test SYSTEM PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(api_server_test PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

target_include_directories(api_server_test SYSTEM PRIVATE ${JSONC_INCLUDE_DIR})
target_link_libraries(api_server_test PRIVATE ${JSONC_LIBRARY})

if(LIBM)
    target_link_libraries(api_server_test PRIVATE m)
endif()

target_link_libraries(api_server_test PRIVATE csnippets)
if(Threads_FOUND)
    target_link_libraries(api_server_test PRIVATE Threads::Threads)
endif()

target_sources(api_server_test
    PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    "${CMAKE_CURRENT_BINARY_DIR}/version.c"
)

add_test(NAME api_server_test COMMAND api_server_test)
add_dependencies(check api_server_test)
