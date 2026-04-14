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

option(USE_ATOMIC_LOCK "Enable atomic lock" OFF)
if (NOT USE_ATOMIC_LOCK)
	list(REMOVE_ITEM CLUSTER_SRC "${CMAKE_CURRENT_SOURCE_DIR}/ub_atomic_dist_lock.c")
endif()

link_directories(${OGRACDB_LIB} "${OGRACDB_LIBRARY}/protobuf/lib")
# generate static library
add_library(ogcluster STATIC ${CLUSTER_SRC})
if (USE_FUZZASAN)
	add_compile_options(-fsanitize-coverage=trace-pc)
endif(USE_FUZZASAN)

if (USE_ATOMIC_LOCK)
	target_compile_definitions(ogcluster PRIVATE USE_ATOMIC_LOCK=1)
    target_link_libraries(ogcluster PRIVATE ogrc ogtms ogfdsa)
else()
	target_compile_definitions(ogcluster PRIVATE USE_ATOMIC_LOCK=0)
    target_link_libraries(ogcluster PRIVATE ogrc ogtms ogfdsa hcom ubsm_sdk ubturbo_tdsql)
endif()