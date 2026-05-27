target_sources(csnippets
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/base64.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/json.c"
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/base64.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/json.h"
)
