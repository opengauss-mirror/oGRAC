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

option(USE_ATOMIC_LOCK "Use in-tree ub_atomic_dist_lock.c instead of external lib" OFF)

# libubs-atomic paths (override via -DUBS_ATOMIC_INCLUDE_DIR=... -DUBS_ATOMIC_LIB_DIR=...)
# Headers vendored under pkg/src/cluster/ by default for offline build.
set(UBS_ATOMIC_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}" CACHE PATH "ubs-atomic public headers")
set(UBS_ATOMIC_LIB_DIR "/usr/lib64" CACHE PATH "Directory containing libubs-atomic.so")

if (USE_ATOMIC_LOCK)
	# aux_source_directory picks up every .c; exclude LOCK=0-only sources.
	list(FILTER CLUSTER_SRC EXCLUDE REGEX "(^|/)ub_gbp_lock_ubturbo_helper\\.c$")
else()
	# Match any path suffix; aux_source_directory path format varies by CMake version.
	list(FILTER CLUSTER_SRC EXCLUDE REGEX "(^|/)ub_atomic_dist_lock\\.c$")
	list(APPEND CLUSTER_SRC "${CMAKE_CURRENT_SOURCE_DIR}/ub_gbp_lock_ubturbo_helper.c")
endif()

link_directories(${OGRACDB_LIB} "${OGRACDB_LIBRARY}/protobuf/lib")
# generate static library
add_library(ogcluster STATIC ${CLUSTER_SRC})
if (USE_FUZZASAN)
	add_compile_options(-fsanitize-coverage=trace-pc)
endif(USE_FUZZASAN)

if (USE_ATOMIC_LOCK)
	target_compile_definitions(ogcluster PRIVATE USE_ATOMIC_LOCK=1)
	target_link_libraries(ogcluster PRIVATE ogrc ogtms ogfdsa hcom ubsm_sdk)
else()
	target_compile_definitions(ogcluster PRIVATE USE_ATOMIC_LOCK=0)
	target_include_directories(ogcluster PUBLIC "${UBS_ATOMIC_INCLUDE_DIR}")
	target_link_directories(ogcluster PUBLIC "${UBS_ATOMIC_LIB_DIR}")
	target_link_libraries(ogcluster PRIVATE ogrc ogtms ogfdsa hcom ubsm_sdk)
	target_link_libraries(ogcluster PUBLIC ubs-atomic)
	if(NOT "${UBS_ATOMIC_LIB_DIR}" STREQUAL "/usr/lib64" AND NOT "${UBS_ATOMIC_LIB_DIR}" STREQUAL "/usr/lib")
		target_link_options(ogcluster PUBLIC "-Wl,-rpath,${UBS_ATOMIC_LIB_DIR}")
	endif()
endif()
