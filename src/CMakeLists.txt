add_executable(multiplexd
    util.c util.h
    conf.c conf.h conf_schema.gen.c conf_schema.gen.h
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

# Generated files contain gperf output that does not conform to project
# warning settings; disable all warnings for them here instead of using
# #pragma inside the generated source.
set_source_files_properties(
    ${CMAKE_CURRENT_SOURCE_DIR}/conf_schema.gen.c
    PROPERTIES COMPILE_OPTIONS "-w")

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

# find a TLS library
set(WITH_TLS FALSE)
set(WITH_OPENSSL FALSE)
set(WITH_MBEDTLS FALSE)
set(TLS_SOURCES "")
set(GENCERTS_SOURCES "")
set(TLS_INCLUDES "")
set(TLS_LIBS "")

set(_tls_lib_effective "${USE_TLS_LIBRARY}")

set(_tls_openssl_found FALSE)
if(_tls_lib_effective STREQUAL "auto" OR _tls_lib_effective STREQUAL "openssl")
    if(BUILD_STATIC OR LINK_STATIC_LIBS)
        set(OPENSSL_USE_STATIC_LIBS TRUE)
    endif()
    find_package(OpenSSL 3.0 QUIET)
    if(OpenSSL_FOUND AND TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
        set(_tls_openssl_found TRUE)
    endif()
endif()

set(_tls_mbedtls_found FALSE)
set(_tls_mbedtls_version "")
if(_tls_lib_effective STREQUAL "auto" OR _tls_lib_effective STREQUAL "mbedtls")
    find_path(MBEDTLS_INCLUDE_DIR NAMES mbedtls/build_info.h)
    if(BUILD_STATIC OR LINK_STATIC_LIBS)
        find_library(MBEDTLS_SSL_LIBRARY NAMES libmbedtls.a)
        find_library(MBEDTLS_X509_LIBRARY NAMES libmbedx509.a)
        find_library(MBEDTLS_CRYPTO_LIBRARY NAMES libmbedcrypto.a)
    else()
        find_library(MBEDTLS_SSL_LIBRARY NAMES mbedtls)
        find_library(MBEDTLS_X509_LIBRARY NAMES mbedx509)
        find_library(MBEDTLS_CRYPTO_LIBRARY NAMES mbedcrypto)
    endif()
    if(EXISTS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h"
       AND EXISTS "${MBEDTLS_SSL_LIBRARY}"
       AND EXISTS "${MBEDTLS_X509_LIBRARY}"
       AND EXISTS "${MBEDTLS_CRYPTO_LIBRARY}")
        file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h"
            _tls_mbedtls_version_line
            REGEX "^#define MBEDTLS_VERSION_NUMBER[ \t]+0x[0-9A-Fa-f]+")
        file(STRINGS "${MBEDTLS_INCLUDE_DIR}/mbedtls/build_info.h"
            _tls_mbedtls_version_str
            REGEX "^#define MBEDTLS_VERSION_STRING[ \t]+\"[^\"]+\"")
        string(REGEX REPLACE
            ".*0x([0-9A-Fa-f]+).*" "\\1"
            _tls_mbedtls_version_hex "${_tls_mbedtls_version_line}")
        string(REGEX REPLACE
            ".*\"([^\"]+)\".*" "\\1"
            _tls_mbedtls_version "${_tls_mbedtls_version_str}")
        # Require mbedTLS >= 3.6 (TLS 1.3 LTS).
        if(_tls_mbedtls_version_hex AND
           NOT "0x${_tls_mbedtls_version_hex}" VERSION_LESS "0x03060000")
            set(_tls_mbedtls_found TRUE)
        endif()
    endif()
endif()

if(_tls_lib_effective STREQUAL "auto")
    if(_tls_openssl_found)
        set(_tls_lib_effective "openssl")
    elseif(_tls_mbedtls_found)
        set(_tls_lib_effective "mbedtls")
    else()
        set(_tls_lib_effective "none")
    endif()
endif()

if(_tls_lib_effective STREQUAL "openssl")
    if(NOT _tls_openssl_found)
        message(FATAL_ERROR "USE_TLS_LIBRARY=openssl requested but OpenSSL >= 3.0 not found")
    endif()
    message(STATUS "TLS library: OpenSSL ${OPENSSL_VERSION}: ${OPENSSL_LIBRARIES}")
    set(WITH_TLS TRUE)
    set(WITH_OPENSSL TRUE)
    set(TLS_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/tlsutil.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tlsutil_openssl.c)
    set(GENCERTS_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/gencerts.c
        ${CMAKE_CURRENT_SOURCE_DIR}/gencerts.h)
    set(TLS_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(TLS_LIBS OpenSSL::SSL OpenSSL::Crypto)
elseif(_tls_lib_effective STREQUAL "mbedtls")
    if(NOT _tls_mbedtls_found)
        message(FATAL_ERROR "USE_TLS_LIBRARY=mbedtls requested but mbedTLS not found")
    endif()
    message(STATUS "TLS library: mbedTLS ${_tls_mbedtls_version}: ${MBEDTLS_SSL_LIBRARY}")
    set(WITH_TLS TRUE)
    set(WITH_MBEDTLS TRUE)
    set(TLS_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/tlsutil.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tlsutil_mbedtls.c)
    set(GENCERTS_SOURCES "")
    set(TLS_INCLUDES ${MBEDTLS_INCLUDE_DIR})
    set(TLS_LIBS ${MBEDTLS_SSL_LIBRARY} ${MBEDTLS_X509_LIBRARY} ${MBEDTLS_CRYPTO_LIBRARY})
elseif(_tls_lib_effective STREQUAL "none")
    message(STATUS "TLS support disabled")
else()
    message(FATAL_ERROR "Invalid USE_TLS_LIBRARY: ${USE_TLS_LIBRARY}")
endif()

if(WITH_TLS)
    target_sources(multiplexd PRIVATE ${TLS_SOURCES} ${GENCERTS_SOURCES})
    target_include_directories(multiplexd SYSTEM PRIVATE ${TLS_INCLUDES})
    target_link_libraries(multiplexd PRIVATE ${TLS_LIBS})
endif()

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
target_link_libraries(multiplexd PRIVATE mux)

# =============================================================================
# Tests
# =============================================================================

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
        target_include_directories(${target_name} SYSTEM PRIVATE ${TLS_INCLUDES})
        target_link_libraries(${target_name} PRIVATE ${TLS_LIBS})
    endif()

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
    add_dependencies(check ${target_name})
endfunction()

# Configuration parser unit tests
add_src_test(conf_test
    conf.c conf.h conf_schema.gen.c conf_schema.gen.h
    conf_test.c
)

# Utility function unit tests
add_src_test(util_test
    util.c util.h
    ${TLS_SOURCES}
    util_test.c
)

# Listener unit tests
add_src_test(listener_test
    util.c util.h
    ${TLS_SOURCES}
    listener.c listener.h
    listener_test.c
)

# Certificate generation tests (always registered; no-op when TLS disabled)
add_src_test(gencerts_test
    ${GENCERTS_SOURCES}
    ${TLS_SOURCES}
    gencerts_test.c
)

# TLS context unit tests (always registered; no-op when TLS disabled)
add_src_test(tlsutil_test
    ${GENCERTS_SOURCES}
    ${TLS_SOURCES}
    tlsutil_test.c
)

# Tunnel unit tests
add_src_test(tunnel_test
    util.c util.h
    conf.c conf.h conf_schema.gen.c conf_schema.gen.h
    ${TLS_SOURCES}
    ${GENCERTS_SOURCES}
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    tunnel_test.c
)
target_link_libraries(tunnel_test PRIVATE mux)

# Server unit tests
add_src_test(server_test
    util.c util.h
    conf.c conf.h conf_schema.gen.c conf_schema.gen.h
    ${TLS_SOURCES}
    ${GENCERTS_SOURCES}
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    server_test.c
)
target_link_libraries(server_test PRIVATE mux)

# API server unit tests
add_src_test(api_server_test
    util.c util.h
    conf.c conf.h conf_schema.gen.c conf_schema.gen.h
    ${TLS_SOURCES}
    ${GENCERTS_SOURCES}
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    api_server_test.c
)
target_link_libraries(api_server_test PRIVATE mux)
