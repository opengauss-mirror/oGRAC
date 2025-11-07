include_directories(
        "${OGRACDB_LIBRARY}/dbstor"
        "${OGRACDB_LIBRARY}/xnet/include"
        "${OGRACDB_SRC}/dbstool"
        "${OGRACDB_SRC}/cms/interface"
)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/ DBS_SRC)


set(DBS_TOTAL_SRC ${DBS_SRC})

# generate static library
add_executable(dbstor ${DBS_TOTAL_SRC} ${VERSION_SRC})
if (USE_FUZZASAN)
	add_compile_options(-fsanitize-coverage=trace-pc)
    target_link_libraries(dbstor PRIVATE zemes zecms zeprotocol zecommon m rt pthread dl z Secodefuzz)
else()
    target_link_libraries(dbstor PRIVATE zemes zecms zeprotocol zecommon m rt pthread dl z)
endif(USE_FUZZASAN)
target_compile_definitions(dbstor PRIVATE -DOG_LIB_VERSION=${DD_OG_LIB_VERSION})
target_compile_definitions(dbstor PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})