# SysSentry defaults aligned with build/detect_syssentry.sh (and build/common.sh).
if(DEFINED OGRAC_DETECT_SYSSENTRY_INCLUDED)
    return()
endif()
set(OGRAC_DETECT_SYSSENTRY_INCLUDED TRUE)

set(OGRAC_SYSSENTRY_DEFAULT_ENABLE_XALARMD OFF)
set(OGRAC_SYSSENTRY_DEFAULT_ENABLE_XALARM_REPORT_EVENT_LEN OFF)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    get_filename_component(_ograc_detect_syssentry_root
        "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
    set(_ograc_detect_syssentry_script
        "${_ograc_detect_syssentry_root}/build/detect_syssentry.sh")
    find_program(_ograc_detect_syssentry_bash bash)
    if(_ograc_detect_syssentry_bash AND EXISTS "${_ograc_detect_syssentry_script}")
        execute_process(
            COMMAND "${_ograc_detect_syssentry_bash}" "${_ograc_detect_syssentry_script}"
            OUTPUT_VARIABLE _ograc_syssentry_detect_out
            RESULT_VARIABLE _ograc_syssentry_detect_rc
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(_ograc_syssentry_detect_rc EQUAL 0)
            string(REPLACE "\n" ";" _ograc_syssentry_detect_lines
                "${_ograc_syssentry_detect_out}")
            foreach(_ograc_syssentry_line IN LISTS _ograc_syssentry_detect_lines)
                if(_ograc_syssentry_line MATCHES "^ENABLE_XALARMD=(.+)$")
                    if(CMAKE_MATCH_1 STREQUAL "ON")
                        set(OGRAC_SYSSENTRY_DEFAULT_ENABLE_XALARMD ON)
                    endif()
                elseif(_ograc_syssentry_line MATCHES "^ENABLE_XALARM_REPORT_EVENT_LEN=(.+)$")
                    if(CMAKE_MATCH_1 STREQUAL "ON")
                        set(OGRAC_SYSSENTRY_DEFAULT_ENABLE_XALARM_REPORT_EVENT_LEN ON)
                    endif()
                endif()
            endforeach()
            message(STATUS "SysSentry detect: ENABLE_XALARMD default=${OGRAC_SYSSENTRY_DEFAULT_ENABLE_XALARMD}, "
                "ENABLE_XALARM_REPORT_EVENT_LEN default=${OGRAC_SYSSENTRY_DEFAULT_ENABLE_XALARM_REPORT_EVENT_LEN}")
        else()
            message(STATUS "SysSentry detect script failed (rc=${_ograc_syssentry_detect_rc}), defaults OFF")
        endif()
    endif()
    unset(_ograc_detect_syssentry_bash)
    unset(_ograc_detect_syssentry_root)
    unset(_ograc_detect_syssentry_script)
    unset(_ograc_syssentry_detect_out)
    unset(_ograc_syssentry_detect_rc)
    unset(_ograc_syssentry_detect_lines)
    unset(_ograc_syssentry_line)
endif()
