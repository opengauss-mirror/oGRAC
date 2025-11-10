include_directories(
        "${CMAKE_CURRENT_SOURCE_DIR}/interface"
        "${OGRACDB_LIBRARY}/dbstor"
        "${OGRACDB_LIBRARY}/xnet/include"
        "${OGRACDB_SRC}/upgrade_check"
        "${OGRACDB_SRC}/cms/cms"
        "${OGRACDB_SRC}/cms/cbb"
)

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/interface INTERFACE_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/cms CMS_SRC)
aux_source_directory(${OGRACDB_SRC}/cms/cbb CBB_SRC)

set(CMS_TOTAL_SRC ${INTERFACE_SRC} ${CMS_SRC} ${CBB_SRC})

# generate static library
add_library(ogcms STATIC ${INTERFACE_SRC})
add_library(ogcmssrc STATIC ${CMS_SRC})
add_library(dsslock SHARED ${CBB_SRC})
add_executable(cms ${CMS_TOTAL_SRC} ${VERSION_SRC})
if (USE_FUZZASAN)
	add_compile_options(-fsanitize-coverage=trace-pc)
    target_link_libraries(cms PRIVATE ogmes ogcms ogprotocol ogcommon m rt pthread dl z Secodefuzz)
else()
    target_link_libraries(cms PRIVATE ogmes ogcms ogprotocol ogcommon m rt pthread dl z)
endif(USE_FUZZASAN)
target_link_libraries(dsslock PRIVATE ogcommon)
target_compile_definitions(cms PRIVATE -DOG_LIB_VERSION=${DD_OG_LIB_VERSION})
target_compile_definitions(cms PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
target_compile_definitions(cms PRIVATE BUILD_CMS_MAIN)