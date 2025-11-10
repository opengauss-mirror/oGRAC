include_directories(
	"${OGRACDB_SRC}/cluster"
	"${OGRACDB_SRC}/rc"
	"${OGRACDB_SRC}/cms/interface"
	"${OGRACDB_SRC}/tms"
)

aux_source_directory(. MEC_SRC)

set(CMAKE_C_FLAGS "-D__LINUX_USR__")

# generate static library
add_library(ogmes STATIC ${MEC_SRC})
target_link_libraries(ogmes PRIVATE ogrc ogtms)