
# test read, write api
set(EXE_NAME test_io)
add_executable(${EXE_NAME} test_fileutils.c)

set(HEADERS ${PARENT_INCLUDE_DIR})

target_sources(${EXE_NAME} PRIVATE
    "${PARENT_SOURCE_DIR}/file_util.c"
    "${PARENT_SOURCE_DIR}/winapi_funcs.c"
    "${PARENT_SOURCE_DIR}/string.c")

target_include_directories(${EXE_NAME} PRIVATE ${HEADERS})
target_include_directories(${EXE_NAME} PRIVATE ${CJSON_INCLUDE_DIR})

target_link_libraries(${EXE_NAME} PRIVATE cjson)




add_test(NAME test_io COMMAND ${CMAKE_INSTALL_BINDIR}/${EXE_NAME})