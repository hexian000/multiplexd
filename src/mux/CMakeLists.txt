# Generated file contains gperf output; disable all warnings for it.
set_source_files_properties(
    "${CMAKE_CURRENT_SOURCE_DIR}/proto_schema.gen.c"
    PROPERTIES COMPILE_OPTIONS "-w")

# The mux protocol stack, compiled once and reused by the main executable
# and by black-box tests.  An OBJECT library keeps link semantics identical
# to compiling the sources directly (no archive symbol selection), which is
# required for coexistence with the white-box tests below and for IPO/LTO.
add_library(mux OBJECT
    recv.c recv.h
    estimator.c estimator.h
    frame.c frame.h
    handshake.c handshake.h
    proto_schema.gen.c proto_schema.gen.h
    mux.c mux.h
    sched.c sched.h
    send.c send.h
    session.c session.h
    stream.c stream.h
    unacked.c unacked.h
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

# Black-box: links the entire real mux library (no mocks) and drives it through
# its public API.  This is the only mux test that exercises the assembled stack
# (two sessions over a socketpair on one ev_loop, plus a raw peer).
add_mux_test(mux_test
    mux_test.c
)
target_link_libraries(mux_test PRIVATE mux)

# White-box: compiles frame.c into the TU.  frame.c is a leaf module, so no
# collaborators are mocked.
add_mux_test(frame_test
    frame_test.c
)

add_mux_test(handshake_test
    frame.c frame.h
    proto_schema.gen.c proto_schema.gen.h
    handshake_test.c
)

add_mux_test(estimator_test
    estimator_test.c
)

# White-box: compiles wire.c into the TU.  wire.c is self-contained (TLS +
# real socket I/O); only the leaf frame.c is linked, no collaborators mocked.
add_mux_test(wire_test
    ${GENCERTS_SOURCES}
    frame.c frame.h
    wire_test.c
)

add_mux_test(sched_test
    sched_test.c
)

# White-box: compiles session.c into the TU with every sibling module mocked;
# only the leaf frame.c is linked.
add_mux_test(session_test
    frame.c frame.h
    session_test.c
)

# White-box: compiles send.c into the TU with spied collaborators to reach
# the static egress-flush state machine (session_flush / session_flush_inline).
add_mux_test(send_test
    send_test.c
)

# White-box: compiles recv.c into the TU with spied collaborators to reach the
# static frame-decode/dispatch helpers and the receive-driven window updates.
add_mux_test(recv_test
    recv_test.c
)

# White-box: compiles stream.c into the TU with mocked sched/send/wire
# collaborators; only the leaf frame.c is linked.
add_mux_test(stream_test
    frame.c frame.h
    stream_test.c
)

# White-box: compiles unacked.c into the TU.  unacked.c is a leaf that only
# uses the real frame.c ring/allocator, so frame.c is linked, not mocked.
add_mux_test(unacked_test
    frame.c frame.h
    unacked_test.c
)
