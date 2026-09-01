#### ogbackup ####
aux_source_directory(. ogbackup_SRC)
set(OGBAK_RESTORE_COMMON_SRC
        ${CMAKE_SOURCE_DIR}/pkg/src/kernel/common/knl_compress.c
        ${CMAKE_SOURCE_DIR}/pkg/src/kernel/backup/bak_format_reader.c
        ${CMAKE_SOURCE_DIR}/pkg/src/kernel/backup/bak_offline_decoder.c
        ${CMAKE_SOURCE_DIR}/pkg/src/kernel/backup/bak_page_restore.c
        ${CMAKE_SOURCE_DIR}/pkg/src/kernel/backup/bak_storage_adapter.c
        ${CMAKE_SOURCE_DIR}/pkg/src/kernel/backup/bak_ctrl_restore.c
        ${CMAKE_SOURCE_DIR}/pkg/src/server/srv_device_adpt.c)

if (USE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
    ADD_EXECUTABLE(ogbackup ${ogbackup_SRC} ${OGBAK_RESTORE_COMMON_SRC} ${VERSION_SRC})
    target_link_libraries(ogbackup PRIVATE ogcommon Secodefuzz)
else ()
    ADD_EXECUTABLE(ogbackup ${ogbackup_SRC} ${OGBAK_RESTORE_COMMON_SRC} ${VERSION_SRC})
    target_link_libraries(ogbackup PRIVATE ogcommon ogclient z zstd lz4)
endif(USE_FUZZASAN)
target_compile_definitions(ogbackup PRIVATE -DOG_LIB_VERSION=${DD_OG_LIB_VERSION})
target_compile_definitions(ogbackup PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
