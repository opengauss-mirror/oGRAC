include_directories(
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

set(source_dir ${CMAKE_CURRENT_SOURCE_DIR}/m.exp)

aux_source_directory(. ODBC_OGCONN_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/common/variant COMMON_VARIANT_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/driver/ogconn OGCONN_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/common COMMON_SRC)
aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/protocol PROTOCOL_SRC)

list(REMOVE_ITEM TMP_SRCS
    ${OGRAC_SRC}/common/cm_util.c
    ${OGRAC_SRC}/common/cm_kmc.c
    ${OGRAC_SRC}/common/cm_uuid.c
    ${OGRAC_SRC}/common/cm_pbl.c
    ${OGRAC_SRC}/common/cm_regexp.c
    ${OGRAC_SRC}/common/cm_raft.c
)

link_directories(${OGRACDB_LIB} ${PCRE_LIB_PATH} ${VPP_LIB_PATH} ${Z_LIB_PATH})

set(ODBC_OGRAC_SRC
    ${COMMON_VARIANT_SRC}
    ${COMMON_SRC}
    ${ODBC_OGCONN_SRC}
    ${PROTOCOL_SRC}
    ${DRIVER_VERSION_SRC}
    ${OGCONN_SRC}
)

add_compile_definitions(GET_DRIVER_VERSION=${DD_CT_LIB_VER_APINAME})
add_compile_definitions(OG_DRIVER_VERSION=${DD_CT_DRIVER_VERSION})

add_compile_options(-Wl,-z,now)

add_library(ogodbc_static STATIC ${ODBC_OGRAC_SRC})

add_library(ogodbc SHARED ${ODBC_OGRAC_SRC})

set_target_properties(ogodbc_static PROPERTIES OUTPUT_NAME ogodbc CLEAN_DIRECT_OUTPUT 1 ARCHIVE_OUTPUT_DIRECTORY ${OGRACDB_LIB})
set_target_properties(ogodbc PROPERTIES OUTPUT_NAME ogodbc CLEAN_DIRECT_OUTPUT 1 ARCHIVE_OUTPUT_DIRECTORY ${OGRACDB_LIB})

option(USE_FUZZASAN OFF)
if(USE_FUZZASAN)
    target_link_libraries(ogodbc PRIVATE pthread dl m rt pcre2-8 -Wl,--version-script=${source_dir} -Wl,--whole-archive ${vpp_libsecurec} ${vpp_libipsi_crypto} ${vpp_libipsi_ssl} -Wl,--no-whole-archive Secodefuzz)
else()
    target_link_libraries(ogodbc PRIVATE pthread dl m rt pcre2-8 -Wl,--version-script=${source_dir} -Wl,--whole-archive ${vpp_libsecurec} ${vpp_libipsi_crypto} ${vpp_libipsi_ssl} -Wl,--no-whole-archive)
endif(USE_FUZZASAN)