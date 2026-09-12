add_library(shim OBJECT
    util.c util.h
    tls.h
)
if(WITH_OPENSSL)
    target_sources(shim PRIVATE tls_openssl.c)
elseif(WITH_MBEDTLS)
    target_sources(shim PRIVATE tls_mbedtls.c)
endif()

target_include_directories(shim PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
# util.h includes <ev.h> for CHECK_REVENTS, so every shim source -- and every
# consumer of that header -- needs libev's include directory.  Nothing here
# calls into libev, so it is not linked.
target_include_directories(shim SYSTEM PUBLIC ${LIBEV_INCLUDE_DIR})
if(WITH_TLS)
    target_include_directories(shim SYSTEM PUBLIC ${TLS_INCLUDES})
endif()

target_compile_options(shim PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/../config.h")
target_compile_options(shim PRIVATE -pedantic -Wall -Wextra -Werror)

if(FORCE_POSIX)
    target_compile_definitions(shim PRIVATE _POSIX_C_SOURCE=200809L)
else()
    target_compile_definitions(shim PRIVATE _GNU_SOURCE)
endif()

target_link_libraries(shim PUBLIC csnippets)
if(WITH_TLS)
    target_link_libraries(shim PUBLIC ${TLS_LIBS})
endif()

if(NOT BUILD_TESTING)
    return()
endif()

function(add_shim_test target_name)
    add_executable(${target_name} ${ARGN})

    target_include_directories(${target_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
    target_include_directories(${target_name} PRIVATE ${CMAKE_SOURCE_DIR}/contrib/csnippets)

    target_compile_options(${target_name} PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/../config.h")
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

    if(LIBATOMIC)
        target_link_libraries(${target_name} PRIVATE ${LIBATOMIC})
    endif()

    target_link_libraries(${target_name} PRIVATE csnippets shim)
    if(Threads_FOUND)
        target_link_libraries(${target_name} PRIVATE Threads::Threads)
    endif()

    add_test(NAME ${target_name} COMMAND ${target_name})
    add_dependencies(check ${target_name})
endfunction()

add_shim_test(util_test
    util_test.c
)

add_shim_test(tls_test
    ${GENCERTS_SOURCES}
    tls_test.c
)
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/tmp")
target_compile_definitions(tls_test PRIVATE TLS_TEST_TMPDIR="${CMAKE_BINARY_DIR}/tmp")

# White-box: compiles tls_openssl.c into the test TU to reach the static
# certificate-strength floor helpers (tls_ec_curve_allowed /
# tls_cert_digest_allowed / tls_verify_cert_strength_cb) and the server's PSK
# identity checks (psk_find_session_cb).  No black-box handshake can present a
# sub-floor certificate -- OpenSSL refuses to load one -- or a hostile PSK
# identity, so they are unreachable through the public API.  Must NOT link
# `shim`, which would duplicate tls_openssl.c's public symbols; util.c is
# compiled in directly for the shared alpn_tokenize() helper tls_openssl.c uses.
if(WITH_OPENSSL)
    add_executable(tls_openssl_test tls_openssl_test.c util.c)
    target_include_directories(tls_openssl_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
    target_include_directories(tls_openssl_test PRIVATE ${CMAKE_SOURCE_DIR}/contrib/csnippets)
    target_include_directories(tls_openssl_test SYSTEM PRIVATE ${LIBEV_INCLUDE_DIR})
    target_include_directories(tls_openssl_test SYSTEM PRIVATE ${TLS_INCLUDES})

    target_compile_options(tls_openssl_test PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/../config.h")
    target_compile_options(tls_openssl_test PRIVATE -pedantic -Wall -Wextra -Werror)

    if(FORCE_POSIX)
        target_compile_definitions(tls_openssl_test PRIVATE _POSIX_C_SOURCE=200809L)
    else()
        target_compile_definitions(tls_openssl_test PRIVATE _GNU_SOURCE)
    endif()

    target_link_libraries(tls_openssl_test PRIVATE csnippets ${TLS_LIBS})

    add_test(NAME tls_openssl_test COMMAND tls_openssl_test)
    add_dependencies(check tls_openssl_test)
endif()

# White-box: compiles tls_mbedtls.c into the test TU to reach its static
# error-classification helpers (map_io_error and the socket-offload BIO
# callbacks), its private context layout and the server's PSK identity checks
# (psk_lookup_cb).  The codes the helpers translate come from the library or the
# kernel, and the public API only offers well-formed PSK labels, so no black-box
# handshake can present a chosen code or a hostile identity.  Must NOT link
# `shim`, which would duplicate tls_mbedtls.c's public symbols; util.c is
# compiled in directly for sock_would_block(), the shared transient-backpressure
# predicate.
if(WITH_MBEDTLS)
    add_executable(tls_mbedtls_test tls_mbedtls_test.c util.c)
    target_include_directories(tls_mbedtls_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
    target_include_directories(tls_mbedtls_test PRIVATE ${CMAKE_SOURCE_DIR}/contrib/csnippets)
    target_include_directories(tls_mbedtls_test SYSTEM PRIVATE ${LIBEV_INCLUDE_DIR})
    target_include_directories(tls_mbedtls_test SYSTEM PRIVATE ${TLS_INCLUDES})

    target_compile_options(tls_mbedtls_test PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/../config.h")
    target_compile_options(tls_mbedtls_test PRIVATE -pedantic -Wall -Wextra -Werror)

    if(FORCE_POSIX)
        target_compile_definitions(tls_mbedtls_test PRIVATE _POSIX_C_SOURCE=200809L)
    else()
        target_compile_definitions(tls_mbedtls_test PRIVATE _GNU_SOURCE)
    endif()

    target_link_libraries(tls_mbedtls_test PRIVATE csnippets ${TLS_LIBS})

    add_test(NAME tls_mbedtls_test COMMAND tls_mbedtls_test)
    add_dependencies(check tls_mbedtls_test)
endif()
