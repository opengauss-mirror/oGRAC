include_directories(
        "${CMAKE_CURRENT_SOURCE_DIR}/interface"
        "${OGRACDB_LIBRARY}/dbstor"
        "${OGRACDB_LIBRARY}/xnet/include"
        "${OGRACDB_SRC}/upgrade_check"
        "${OGRACDB_SRC}/cms/cms"
        "${OGRACDB_SRC}/cms/cbb"
)

include("${CMAKE_CURRENT_SOURCE_DIR}/../../../build/cmake_include/OgracDetectSysSentry.cmake")
option(ENABLE_XALARMD "add sysSentry libxalarm plugin support"
    ${OGRAC_SYSSENTRY_DEFAULT_ENABLE_XALARMD})
option(ENABLE_XALARM_REPORT_EVENT_LEN "xalarm_report_event third len parameter (new libxalarm ABI)"
    ${OGRAC_SYSSENTRY_DEFAULT_ENABLE_XALARM_REPORT_EVENT_LEN})

if(ENABLE_XALARMD)
    message(STATUS "ENABLE_XALARMD is ON")
    add_definitions(-DENABLE_XALARMD)

    if(ENABLE_XALARM_REPORT_EVENT_LEN)
        message(STATUS "Using new libxalarm ABI (CM_XALARM_REPORT_EVENT_HAS_LEN)")
        add_definitions(-DCM_XALARM_REPORT_EVENT_HAS_LEN)
    else()
        message(STATUS "Using legacy libxalarm ABI (CM_XALARM_LEGACY_REGISTER_ABI)")
        add_definitions(-DCM_XALARM_LEGACY_REGISTER_ABI)
    endif()
endif()

aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/interface INTERFACE_SRC)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/cms CMS_SRC)
aux_source_directory(${OGRACDB_SRC}/cms/cbb CBB_SRC)

set(CMS_TOTAL_SRC ${INTERFACE_SRC} ${CMS_SRC} ${CBB_SRC})

# generate static library
add_library(ogcms STATIC ${INTERFACE_SRC})
add_library(ogcmssrc STATIC ${CMS_SRC})
add_library(dsslock SHARED ${CBB_SRC})
add_executable(cms ${CMS_TOTAL_SRC} ${VERSION_SRC})
set(CMS_LINK_LIBS ogmes ogcms ogprotocol ogcommon m rt pthread dl z)
if(ENABLE_XALARMD)
    list(APPEND CMS_LINK_LIBS xalarm)
endif()
if (USE_FUZZASAN)
	add_compile_options(-fsanitize-coverage=trace-pc)
    target_link_libraries(cms PRIVATE ${CMS_LINK_LIBS} Secodefuzz)
else()
    target_link_libraries(cms PRIVATE ${CMS_LINK_LIBS})
endif(USE_FUZZASAN)
target_link_libraries(dsslock PRIVATE ogcommon)
target_compile_definitions(cms PRIVATE -DOG_LIB_VERSION=${DD_OG_LIB_VERSION})
target_compile_definitions(cms PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
target_compile_definitions(cms PRIVATE BUILD_CMS_MAIN)
