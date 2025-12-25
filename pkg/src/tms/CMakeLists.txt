aux_source_directory(. TMS_SRC)

# generate static library
add_library(ogtms STATIC ${TMS_SRC})