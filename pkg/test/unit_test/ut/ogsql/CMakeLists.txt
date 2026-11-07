message(STATUS "build ogsql_vertical_ut...")

include_directories(${CMAKE_SOURCE_DIR}/pkg/src/common)
include_directories(${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql)

add_executable(ogsql_vertical_test
    ${CMAKE_CURRENT_SOURCE_DIR}/ogsql_vertical_test.c
    ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_vertical.c)
set_target_properties(ogsql_vertical_test PROPERTIES LINKER_LANGUAGE C)
