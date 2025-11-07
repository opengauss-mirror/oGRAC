include_directories(
	"${OGRACDB_SRC}/cluster"
	"${OGRACDB_SRC}/rc"
        "${OGRACDB_SRC}/cms/interface"
)

#### ogbox ####
aux_source_directory(. OGBOX_SRC)
add_executable(ogbox ${OGBOX_SRC} ${VERSION_SRC})
if (USE_FUZZASAN)
    target_link_libraries(ogbox PRIVATE -Wl,--start-group zeserver zesql zemes zeprotocol zekernel zeclient zecommon zecluster zecms zerc m rt pthread dl z zstd lz4 Secodefuzz -Wl,--end-group)
else()
    target_link_libraries(ogbox PRIVATE -Wl,--start-group zeserver zesql zemes zeprotocol zekernel zeclient zecommon zecluster zecms zerc m rt pthread dl z zstd lz4 -Wl,--end-group)
endif(USE_FUZZASAN)
target_compile_definitions(ogbox PRIVATE -DOG_LIB_VERSION=${DD_OG_LIB_VERSION})
target_compile_definitions(ogbox PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
