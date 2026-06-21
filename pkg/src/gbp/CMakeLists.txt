set(GBPS_SRC
    main.cpp
    gbp_config.cpp
    gbp_state.cpp
    gbp_protocol.cpp
    gbp_server.cpp
    gbp_admin.cpp
)

add_executable(gbps ${GBPS_SRC})
target_include_directories(gbps PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(gbps PRIVATE cxx_std_17)
set(GBPS_CFG_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/../../cfg/gbps.conf")

if(DEFINED OGRACDB_BIN)
    add_custom_command(TARGET gbps POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_CURRENT_SOURCE_DIR}/gbps_ctl
                ${OGRACDB_BIN}/gbps_ctl
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_CURRENT_SOURCE_DIR}/gbps_contrl.sh
                ${OGRACDB_BIN}/gbps_contrl.sh
    )
    if(UNIX)
        add_custom_command(TARGET gbps POST_BUILD
            COMMAND chmod 500 ${OGRACDB_BIN}/gbps_ctl ${OGRACDB_BIN}/gbps_contrl.sh
        )
    endif()
endif()

if(UNIX)
    target_link_libraries(gbps PRIVATE pthread)
endif()

if(WIN32)
    target_link_libraries(gbps PRIVATE ws2_32)
endif()

install(TARGETS gbps RUNTIME DESTINATION bin)
install(PROGRAMS gbps_ctl gbps_contrl.sh DESTINATION bin)
install(FILES ${GBPS_CFG_SOURCE} DESTINATION cfg)
