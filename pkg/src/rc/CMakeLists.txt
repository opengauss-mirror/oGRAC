include_directories(
        "${OGRACDB_SRC}/cms/interface"
)

aux_source_directory(. RC_SRC)

# generate static library
add_library(ogrc STATIC ${RC_SRC})
if (USE_FUZZASAN)
        add_compile_options(-fsanitize-coverage=trace-pc)
        target_link_libraries(ogrc PRIVATE ogcms Secodefuzz)
else ()
        target_link_libraries(ogrc PRIVATE ogcms)
endif(USE_FUZZASAN)
