#### ogbackup ####
aux_source_directory(. ogbackup_SRC)

if (USE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
    ADD_EXECUTABLE(ogbackup ${ogbackup_SRC} ${VERSION_SRC})
    target_link_libraries(ogbackup PRIVATE ogcommon Secodefuzz)
else ()
    ADD_EXECUTABLE(ogbackup ${ogbackup_SRC} ${VERSION_SRC})
    target_link_libraries(ogbackup PRIVATE ogcommon ogclient)
endif(USE_FUZZASAN)
target_compile_definitions(ogbackup PRIVATE -DOG_LIB_VERSION=${DD_OG_LIB_VERSION})
target_compile_definitions(ogbackup PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})
