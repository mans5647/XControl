
# test read, write api
set(EXE_NAME_GET_SERVICES test_get_services)
add_executable(${EXE_NAME_GET_SERVICES} win_api_get_services.c)

set(HEADERS ${PARENT_INCLUDE_DIR})

target_sources(${EXE_NAME_GET_SERVICES} PRIVATE
    "${PARENT_SOURCE_DIR}/file_util.c"
    "${PARENT_SOURCE_DIR}/winapi_funcs.c"
    "${PARENT_SOURCE_DIR}/string.c"
    "${PARENT_SOURCE_DIR}/OSInfo.c")

target_include_directories(${EXE_NAME_GET_SERVICES} PRIVATE ${HEADERS})
target_include_directories(${EXE_NAME_GET_SERVICES} PRIVATE ${CJSON_INCLUDE_DIR})

target_link_libraries(${EXE_NAME_GET_SERVICES} PRIVATE cjson)




add_test(NAME test_get_services COMMAND ${CMAKE_INSTALL_BINDIR}/${EXE_NAME_GET_SERVICES})