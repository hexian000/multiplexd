target_sources(multiplexd
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/dispatch.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/estimator.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/frame.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/handshake.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/mux.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/sched.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/session.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/stream.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/wire.c"
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/estimator.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/frame.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/handshake.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/mux.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/sched.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/session.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/stream.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/wire.h"
)

function(add_mux_test target_name)
    add_executable(${target_name}
        ../util.c ../util.h
        ../jsonutil.c ../jsonutil.h
        ${TLS_SOURCES}
        ${ARGN}
    )

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

    if(WITH_TLS)
        target_include_directories(${target_name} SYSTEM PRIVATE ${TLS_INCLUDES})
        target_link_libraries(${target_name} PRIVATE ${TLS_LIBS})
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
        "${CMAKE_CURRENT_BINARY_DIR}/../config.h"
        "${CMAKE_CURRENT_BINARY_DIR}/../version.c"
    )

    add_test(NAME ${target_name} COMMAND ${target_name})
    set_tests_properties(${target_name} PROPERTIES
        ENVIRONMENT "LSAN_OPTIONS=suppressions=${CMAKE_BINARY_DIR}/lsan.supp"
    )
    add_dependencies(check ${target_name})
endfunction()

# Mux unit tests (mux_stream_send / mux_stream_recv direct I/O mode)
add_mux_test(mux_test
    dispatch.c dispatch.h
    estimator.c estimator.h
    mux.c mux.h
    frame.c frame.h
    sched.c sched.h
    session.c session.h
    stream.c stream.h
    wire.c wire.h
    mux_test.c
)

add_mux_test(frame_test
    frame.c frame.h
    frame_test.c
)

add_mux_test(handshake_test
    frame.c frame.h
    handshake_test.c
)

add_mux_test(estimator_test
    estimator_test.c
)

add_mux_test(dispatch_test
    frame.c frame.h
    dispatch_test.c
)

add_mux_test(dispatch_fuzz_test
    frame.c frame.h
    dispatch_fuzz_test.c
)

add_mux_test(wire_test
    frame.c frame.h
    wire.c wire.h
    ${GENCERTS_SOURCES}
    wire_test.c
)

add_mux_test(sched_test
    sched_test.c
)

add_mux_test(session_test
    dispatch.c dispatch.h
    estimator.c estimator.h
    frame.c frame.h
    handshake.c handshake.h
    mux.c mux.h
    sched.c sched.h
    session.c session.h
    stream.c stream.h
    wire.c wire.h
    session_test.c
)

add_mux_test(mux_api_test
    dispatch.c dispatch.h
    estimator.c estimator.h
    frame.c frame.h
    handshake.c handshake.h
    mux.c mux.h
    sched.c sched.h
    session.c session.h
    stream.c stream.h
    wire.c wire.h
    mux_api_test.c
)

add_mux_test(stream_test
    dispatch.c dispatch.h
    estimator.c estimator.h
    frame.c frame.h
    handshake.c handshake.h
    mux.c mux.h
    sched.c sched.h
    session.c session.h
    stream.c stream.h
    wire.c wire.h
    stream_test.c
)
