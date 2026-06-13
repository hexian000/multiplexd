# Generated file contains gperf output; disable all warnings for it.
set_source_files_properties(
    "${CMAKE_CURRENT_SOURCE_DIR}/proto_schema.gen.c"
    PROPERTIES COMPILE_OPTIONS "-w")

# The mux protocol stack, compiled once and reused by the main executable
# and by black-box tests.  An OBJECT library keeps link semantics identical
# to compiling the sources directly (no archive symbol selection), which is
# required for coexistence with the white-box tests below and for IPO/LTO.
add_library(mux OBJECT
    dispatch.c dispatch.h
    estimator.c estimator.h
    frame.c frame.h
    handshake.c handshake.h
    proto_schema.gen.c proto_schema.gen.h
    mux.c mux.h
    sched.c sched.h
    session.c session.h
    stream.c stream.h
    wire.c wire.h
)

target_include_directories(mux PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_include_directories(mux SYSTEM PUBLIC ${LIBEV_INCLUDE_DIR})

target_compile_options(mux PRIVATE "-include${CMAKE_CURRENT_BINARY_DIR}/../config.h")
target_compile_options(mux PRIVATE -pedantic -Wall -Wextra -Werror)

if(FORCE_POSIX)
    target_compile_definitions(mux PRIVATE _POSIX_C_SOURCE=200809L)
else()
    target_compile_definitions(mux PRIVATE _GNU_SOURCE)
endif()

target_link_libraries(mux PUBLIC csnippets ${LIBEV_LIBRARY})
if(LIBM)
    target_link_libraries(mux PUBLIC m)
endif()

function(add_mux_test target_name)
    add_executable(${target_name}
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

    if(LIBM)
        target_link_libraries(${target_name} PRIVATE m)
    endif()

    target_link_libraries(${target_name} PRIVATE csnippets)
    if(Threads_FOUND)
        target_link_libraries(${target_name} PRIVATE Threads::Threads)
    endif()

    add_test(NAME ${target_name} COMMAND ${target_name})
    add_dependencies(check ${target_name})
endfunction()

# Mux unit tests (mux_stream_send / mux_stream_recv direct I/O mode)
add_mux_test(mux_test
    dispatch.c dispatch.h
    estimator.c estimator.h
    mux.c mux.h
    frame.c frame.h
    proto_schema.gen.c proto_schema.gen.h
    sched.c sched.h
    session.c session.h
    stream.c stream.h
    wire.c wire.h
    mux_test.c
)

add_mux_test(frame_test
    frame_test.c
)
target_link_libraries(frame_test PRIVATE mux)

add_mux_test(handshake_test
    frame.c frame.h
    proto_schema.gen.c proto_schema.gen.h
    handshake_test.c
)

add_mux_test(handshake_fuzz_test
    frame.c frame.h
    proto_schema.gen.c proto_schema.gen.h
    handshake_fuzz_test.c
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
    ${GENCERTS_SOURCES}
    wire_test.c
)
target_link_libraries(wire_test PRIVATE mux)

add_mux_test(sched_test
    sched_test.c
)

add_mux_test(session_test
    session_test.c
)
target_link_libraries(session_test PRIVATE mux)

add_mux_test(mux_api_test
    mux_api_test.c
)
target_link_libraries(mux_api_test PRIVATE mux)

add_mux_test(stream_test
    stream_test.c
)
target_link_libraries(stream_test PRIVATE mux)
