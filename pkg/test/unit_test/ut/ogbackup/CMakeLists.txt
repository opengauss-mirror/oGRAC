message(STATUS "build ogbackup_ut...")

aux_source_directory(${CMAKE_SOURCE_DIR}/pkg/src/utils/ogbackup ogbackup_SRC)
set(OGBAKUP_UT_SOURCE ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ogbackup/ogbackup_test_main.cpp
                ${CMAKE_SOURCE_DIR}/pkg/test/unit_test/ut/ogbackup/ogbackup_example_test.cpp)
list(REMOVE_ITEM ogbackup_SRC ${CMAKE_SOURCE_DIR}/pkg/src/utils/ogbackup/ogbackup_main.c)

#add_compile_options(-fno-common)
add_compile_options(-Wall -fpermissive)

#add_link_options(-Wl, -Bsymbolic)
add_link_options(-rdynamic)

add_executable(ogbackup_test ${OGBAKUP_UT_SOURCE} ${ogbackup_SRC})
set_target_properties(ogbackup_test PROPERTIES LINKER_LANGUAGE "CXX")

target_link_libraries(ogbackup_test 
                     -Wl,--start-group 
                     gtest mockcpp gmock ogtms ogcms ogprotocol m rt dl z zstd lz4
                     ogcmssrc ogclient ogrc ogcommon ogmes ogfdsa ogcluster
                     ogserver ogkernel ogracsql pthread  z 
                     -Wl,--end-group)
target_compile_definitions(ogbackup_test PRIVATE -DOG_LIB_VERSION=${DD_OG_LIB_VERSION})
target_compile_definitions(ogbackup_test PRIVATE -DGETDBVERSION=${DD_GETDBVERSION})