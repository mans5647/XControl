


set(HEADERS ${PARENT_INCLUDE_DIR})


function(CONFIGURE_EXE exe_name filename)
    add_executable(${exe_name} ${filename})
    
    set(SOURCES "${PARENT_SOURCE_DIR}/file_util.c"
    "${PARENT_SOURCE_DIR}/winapi_funcs.c"
    "${PARENT_SOURCE_DIR}/string.c"
    "${PARENT_SOURCE_DIR}/OSInfo.c"
    "${PARENT_SOURCE_DIR}/resource_monitor.c")

    target_sources(${exe_name} PRIVATE ${SOURCES})
    
    # own include dir
    target_include_directories(${exe_name} PRIVATE ${HEADERS})
    
    # cjson include
    target_include_directories(${exe_name} PRIVATE ${CJSON_INCLUDE_DIR})

    target_link_libraries(${exe_name} PRIVATE cjson)
    add_test(NAME test_${exe_name} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${exe_name})

endfunction()

configure_exe(test_get_services win_api_get_services.c)
configure_exe(test_get_osinfo win_api_test_OSInfo.c)
configure_exe(test_runprocess winapi_run_process.c)

