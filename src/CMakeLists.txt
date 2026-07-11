add_executable(multiplexd
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

set(WITH_TLS FALSE)
set(WITH_OPENSSL FALSE)
set(WITH_MBEDTLS FALSE)
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
if(_tls_lib_effective STREQUAL "auto" OR _tls_lib_effective STREQUAL "mbedtls")
    # Use the CMake package config exported by mbedTLS itself: its imported
    # targets carry the correct include directories and transitive libraries.
    # This is required for mbedTLS >= 4.0, where the crypto layer was split into
    # a separate TF-PSA-Crypto component (relocated headers and libtfpsacrypto),
    # and it also resolves an uninstalled build tree via CMAKE_PREFIX_PATH.
    # No version is passed to find_package: mbedTLS ships a SameMajorVersion
    # compatibility file that rejects a 4.x install for a "3.6" request, so the
    # >= 3.6 floor (TLS 1.3 LTS) is enforced manually below.
    find_package(MbedTLS CONFIG QUIET)
    if(MbedTLS_FOUND AND NOT MbedTLS_VERSION VERSION_LESS "3.6")
        if((BUILD_STATIC OR LINK_STATIC_LIBS) AND TARGET MbedTLS::mbedtls_static)
            set(_tls_mbedtls_target MbedTLS::mbedtls_static)
        elseif(TARGET MbedTLS::mbedtls)
            set(_tls_mbedtls_target MbedTLS::mbedtls)
        elseif(TARGET MbedTLS::mbedtls_static)
            set(_tls_mbedtls_target MbedTLS::mbedtls_static)
        endif()
        if(_tls_mbedtls_target)
            set(_tls_mbedtls_found TRUE)
            set(_tls_mbedtls_version "${MbedTLS_VERSION}")
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
    message(STATUS "OpenSSL ${OPENSSL_VERSION}: ${OPENSSL_LIBRARIES}")
    set(WITH_TLS TRUE)
    set(WITH_OPENSSL TRUE)
    set(GENCERTS_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/gencerts.c
        ${CMAKE_CURRENT_SOURCE_DIR}/gencerts.h)
    set(TLS_INCLUDES ${OPENSSL_INCLUDE_DIR})
    set(TLS_LIBS OpenSSL::SSL OpenSSL::Crypto)
elseif(_tls_lib_effective STREQUAL "mbedtls")
    if(NOT _tls_mbedtls_found)
        message(FATAL_ERROR "USE_TLS_LIBRARY=mbedtls requested but mbedTLS not found")
    endif()
    set(WITH_TLS TRUE)
    set(WITH_MBEDTLS TRUE)
    set(GENCERTS_SOURCES "")
    get_target_property(_tls_mbedtls_location ${_tls_mbedtls_target} LOCATION)
    if(NOT _tls_mbedtls_location)
        set(_tls_mbedtls_location ${_tls_mbedtls_target})
    endif()
    message(STATUS "mbedTLS ${_tls_mbedtls_version}: ${_tls_mbedtls_location}")
    # The imported target propagates its include directories (as SYSTEM)
    # and the transitive x509/crypto libraries on its own.
    set(TLS_INCLUDES "")
    set(TLS_LIBS ${_tls_mbedtls_target})
elseif(_tls_lib_effective STREQUAL "none")
    message(STATUS "TLS support disabled")
else()
    message(FATAL_ERROR "Invalid USE_TLS_LIBRARY: ${USE_TLS_LIBRARY}")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(WITH_CRASH_HANDLER TRUE)
endif()

if(WITH_TLS)
    target_sources(multiplexd PRIVATE ${GENCERTS_SOURCES})
endif()

add_subdirectory(shim)
target_link_libraries(multiplexd PRIVATE shim)

install(TARGETS multiplexd DESTINATION bin)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
    @ONLY)

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

    if(LIBM)
        target_link_libraries(${target_name} PRIVATE m)
    endif()

    target_link_libraries(${target_name} PRIVATE csnippets shim)
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

add_src_test(conf_test
    conf.c conf.h conf_schema.gen.c conf_schema.gen.h
    mux/frame.c mux/frame.h
    conf_test.c
)

add_src_test(listener_test
    listener.c listener.h
    listener_test.c
)

# Always registered; no-op when TLS disabled.
add_src_test(gencerts_test
    ${GENCERTS_SOURCES}
    gencerts_test.c
)

add_src_test(tunnel_test
    conf.c conf.h conf_schema.gen.c conf_schema.gen.h
    ${GENCERTS_SOURCES}
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    tunnel_test.c
)
target_link_libraries(tunnel_test PRIVATE mux)

add_src_test(server_test
    conf.c conf.h conf_schema.gen.c conf_schema.gen.h
    ${GENCERTS_SOURCES}
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    server_test.c
)
target_link_libraries(server_test PRIVATE mux)

add_src_test(api_server_test
    conf.c conf.h conf_schema.gen.c conf_schema.gen.h
    ${GENCERTS_SOURCES}
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    api_server_test.c
)
target_link_libraries(api_server_test PRIVATE mux)

# White-box: compiles main.c into the TU (its main() renamed away) to reach the
# static CLI parser; the daemon body's collaborators are linked real so it
# resolves, but only parse_args/print_usage are exercised.
add_src_test(main_test
    conf.c conf.h conf_schema.gen.c conf_schema.gen.h
    ${GENCERTS_SOURCES}
    listener.c listener.h
    server.c server.h
    tunnel.c tunnel.h
    api_server.c api_server.h
    main_test.c
)
target_link_libraries(main_test PRIVATE mux)
