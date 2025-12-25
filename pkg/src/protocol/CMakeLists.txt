include_directories(
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

link_directories(${OGRACDB_LIB})

aux_source_directory(. PROTOCOL_SRC)

option(USE_FUZZASAN OFF)
if (USE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
endif(USE_FUZZASAN)
# generate static library
add_library(ogprotocol_static STATIC ${PROTOCOL_SRC})
# generate dynamic library
add_library(ogprotocol SHARED ${PROTOCOL_SRC})
# dynamic libraries and static libraries exist at the same time
set_target_properties(ogprotocol PROPERTIES OUTPUT_NAME ogprotocol
        CLEAN_DIRECT_OUTPUT 1
        ARCHIVE_OUTPUT_DIRECTORY ${OGRACDB_LIB}
        )
set_target_properties(ogprotocol_static PROPERTIES OUTPUT_NAME ogprotocol
        CLEAN_DIRECT_OUTPUT 1
        ARCHIVE_OUTPUT_DIRECTORY ${OGRACDB_LIB}
        )
if (USE_FUZZASAN)
    target_link_libraries(ogprotocol PRIVATE ogcommon pthread m rt Secodefuzz)
else ()
    target_link_libraries(ogprotocol PRIVATE ogcommon pthread m rt)
endif(USE_FUZZASAN)
