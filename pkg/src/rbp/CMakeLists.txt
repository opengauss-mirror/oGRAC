set(RBPS_SRC
    main.cpp
    rbp_config.cpp
    rbp_state.cpp
    rbp_protocol.cpp
    rbp_server.cpp
    rbp_admin.cpp
)

add_executable(rbps ${RBPS_SRC})
target_include_directories(rbps PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(rbps PRIVATE cxx_std_17)
set(RBPS_CFG_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/../../cfg/rbps.conf")

if(DEFINED OGRACDB_BIN)
    add_custom_command(TARGET rbps POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_CURRENT_SOURCE_DIR}/rbps_ctl
                ${OGRACDB_BIN}/rbps_ctl
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_CURRENT_SOURCE_DIR}/rbps_contrl.sh
                ${OGRACDB_BIN}/rbps_contrl.sh
    )
    if(UNIX)
        add_custom_command(TARGET rbps POST_BUILD
            COMMAND chmod 500 ${OGRACDB_BIN}/rbps_ctl ${OGRACDB_BIN}/rbps_contrl.sh
        )
    endif()
endif()

if(UNIX)
    target_link_libraries(rbps PRIVATE pthread)
endif()

if(WIN32)
    target_link_libraries(rbps PRIVATE ws2_32)
endif()

install(TARGETS rbps RUNTIME DESTINATION bin)
install(PROGRAMS rbps_ctl rbps_contrl.sh DESTINATION bin)
install(FILES ${RBPS_CFG_SOURCE} DESTINATION cfg)
