include_directories(
	"${OGRACDB_SRC}/cms/interface"
        "${OGRACDB_SRC}/upgrade_check"
#        "${CMAKE_CURRENT_SOURCE_DIR}/concurrency_test"
#        "${CMAKE_CURRENT_SOURCE_DIR}/shard_concurrency_test"
#        "${CMAKE_CURRENT_SOURCE_DIR}/zperf_test"
)

set(EXECUTABLE_OUTPUT_PATH ${OGRACDB_BIN})

#cmake predefinitions
add_compile_definitions(OG_LIB_VERSION=${DD_OG_LIB_VERSION})
add_compile_definitions(GETDBVERSION=${DD_CT_LIB_VER_APINAME})

add_subdirectory(og_regress)
#add_subdirectory(sharding_regress)
#add_subdirectory(concurrency_test)
#add_subdirectory(shard_concurrency_test)
#add_subdirectory(zbak_agent)
#add_subdirectory(odbc_demo)
#add_subdirectory(zperf_test)
add_subdirectory(unit_test)
#add_subdirectory(cluster_test)
#add_subdirectory(oGRAC_fuzz_test)
#add_subdirectory(cms_fuzz_test)