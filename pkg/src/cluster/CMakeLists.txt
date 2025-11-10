include_directories(
	"${OGRACDB_SRC}/rc"
	"${OGRACDB_SRC}/mec"
	"${OGRACDB_SRC}/kernel/common"
	"${OGRACDB_SRC}/cms/interface"
	"${OGRACDB_SRC}/tms"
	"${OGRACDB_SRC}/fdsa"
	"${CMAKE_CURRENT_SOURCE_DIR}"
)

aux_source_directory(. CLUSTER_SRC)
link_directories(${OGRACDB_LIB} "${OGRACDB_LIBRARY}/protobuf/lib")
# generate static library
add_library(ogcluster STATIC ${CLUSTER_SRC})
if (USE_FUZZASAN)
	add_compile_options(-fsanitize-coverage=trace-pc)
endif(USE_FUZZASAN)
target_link_libraries(ogcluster PRIVATE ogrc ogtms ogfdsa)