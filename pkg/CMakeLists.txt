cmake_minimum_required(VERSION 3.12.1)

set(VERSION_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/version/og_version.c)
set(DRIVER_VERSION_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/version/client_version.c)
set(OGSQL_VERSION_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/version/ogsql_version.c)

link_directories(${OGRACDB_LIB} ${OGRACDB_LIBRARY} ${OPENSSL_LIB_PATH} ${PCRE_LIB_PATH} ${Z_LIB_PATH}
        ${ODBC_LIB_PATH} ${VPP_LIB_PATH} ${KMC_LIB_PATH} ${ZSTD_LIB_PATH} ${LZ4_LIB_PATH} ${AES_LIB_PATH}
        ${UUID_LIB_PATH})

set(OGRACDB_TAG "oGRACd_${COMMIT_ID}")
set(EXECUTABLE_OUTPUT_PATH ${OGRACDB_BIN})
set(LIBRARY_OUTPUT_PATH ${OGRACDB_LIB})

MESSAGE(STATUS ${DD_OG_LIB_VERSION})
MESSAGE(STATUS ${DD_CT_LIB_VER_APINAME})

if (UNIX)
    add_compile_definitions(WSEC_COMPILE_CAC_OPENSSL)
    add_compile_definitions(WSEC_USE_OPENSSL_110)
    add_compile_definitions(WSEC_AES_GCM_SUPPORT)
    add_compile_definitions(WSEC_ERR_CODE_BASE=0x10000000)
    add_compile_definitions(WSEC_DEBUG)
    add_compile_definitions(WSEC_TRACE_MEMORY)
    add_compile_definitions(WSEC_COMPILE_MIP_OTHER)
endif ()

# add subdir
add_subdirectory(src)
if(NOT USE_OSS_BUILD)
   add_subdirectory(test)
endif()
