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

# White-box: compiles tls_openssl.c into the test TU to reach the static
# certificate-strength floor helpers (tls_ec_curve_allowed /
# tls_cert_digest_allowed / tls_verify_cert_strength_cb).  No black-box
# handshake can present a sub-floor certificate to them -- OpenSSL refuses to
# load one -- so they are unreachable through the public API.  Must NOT link
# `shim`, which would duplicate tls_openssl.c's public symbols.
if(WITH_OPENSSL)
    add_executable(tls_openssl_test tls_openssl_test.c)
    target_include_directories(tls_openssl_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
    target_include_directories(tls_openssl_test PRIVATE ${CMAKE_SOURCE_DIR}/contrib/csnippets)
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
