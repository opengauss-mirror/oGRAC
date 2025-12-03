##### ogrst ####
set(OGRST_ALL_SRC
        ogrst_main.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_common.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_dump.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_exp_bin.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_export.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_import.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_input_bind_param.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_load.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_option.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr_analyse.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr_common.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr_head.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr_monitor.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr_parameter.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr_segment.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr_session.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr_snap.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr_sql.c
        ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogsql/ogsql_wsr_buffer.c
        )

ADD_EXECUTABLE(ogrst ${OGRST_ALL_SRC} ${VERSION_SRC})
target_include_directories(ogrst PUBLIC
        "${OGRACDB_SRC}/cluster"
        "${OGRACDB_SRC}/rc"
        "${PROJECT_SOURCE_DIR}/src/utils"
        "${PROJECT_SOURCE_DIR}/src/driver/gsc"
        "${OGRACDB_SRC}/cms/interface"
        )
if (USE_FUZZASAN)
    target_link_libraries(ogrst PRIVATE zeserver zesql zemes zeprotocol zekernel zeclient zecommon m rt pthread dl z zstd lz4 Secodefuzz) 
else()
    target_link_libraries(ogrst PRIVATE zeserver zesql zemes zeprotocol zekernel zeclient zecommon m rt pthread dl z zstd lz4)
endif(USE_FUZZASAN)
target_compile_definitions(ogrst PRIVATE -DOG_LIB_VERSION=${DD_OG_LIB_VERSION})
target_compile_definitions(ogrst PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
