#### ogsql ####
aux_source_directory(../ogsql OGSQL_SRC)

if (USE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
    ADD_EXECUTABLE(ogsql ${OGSQL_SRC} ${OGSQL_VERSION_SRC})
    target_link_libraries(ogsql PRIVATE ogracsql ogprotocol ogcommon ogclient m rt pthread dl z Secodefuzz)
else ()
    ADD_EXECUTABLE(ogsql ${OGSQL_SRC} ${OGSQL_VERSION_SRC})
    target_link_libraries(ogsql PRIVATE ogracsql ogprotocol ogcommon ogclient m rt pthread dl z)
endif(USE_FUZZASAN)
target_compile_definitions(ogsql PRIVATE -DOG_OGSQL_VERSION=${DD_OG_OGSQL_VERSION})
target_compile_definitions(ogsql PRIVATE -DGET_OGSQL_VERSION=${DD_GETOGSQLVERSION})
