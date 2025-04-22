
# test compress/decompress
set(EXE_NAME test_compress)
set(E_SCREEN_APP test_screen)

add_executable(${EXE_NAME} test_compress.c)


set(HEADERS ${PARENT_INCLUDE_DIR})

target_sources(${EXE_NAME} PRIVATE
    "${PARENT_SOURCE_DIR}/file_util.c"
    "${PARENT_SOURCE_DIR}/winapi_funcs.c"
    "${PARENT_SOURCE_DIR}/string.c"
    "${PARENT_SOURCE_DIR}/myzip.c")

target_include_directories(${EXE_NAME} PRIVATE ${HEADERS})
target_include_directories(${EXE_NAME} PRIVATE ${CJSON_INCLUDE_DIR})
target_include_directories(${EXE_NAME} PRIVATE ${ZLIB_INCLUDE_DIR})
target_link_libraries(${EXE_NAME} PRIVATE cjson)
target_link_libraries(${EXE_NAME} PRIVATE ${libz_var})

install(TARGETS ${EXE_NAME})





add_executable(${E_SCREEN_APP} test_compress_screen.c)


set(HEADERS ${PARENT_INCLUDE_DIR})

target_sources(${E_SCREEN_APP} PRIVATE
    "${PARENT_SOURCE_DIR}/file_util.c"
    "${PARENT_SOURCE_DIR}/winapi_funcs.c"
    "${PARENT_SOURCE_DIR}/string.c"
    "${PARENT_SOURCE_DIR}/myzip.c")

target_include_directories(${E_SCREEN_APP} PRIVATE ${HEADERS})
target_include_directories(${E_SCREEN_APP} PRIVATE ${CJSON_INCLUDE_DIR})
target_include_directories(${E_SCREEN_APP} PRIVATE ${ZLIB_INCLUDE_DIR})
target_link_libraries(${E_SCREEN_APP} PRIVATE cjson)
target_link_libraries(${E_SCREEN_APP} PRIVATE ${libz_var})



add_test(NAME ${EXE_NAME} COMMAND ${CMAKE_INSTALL_BINDIR}/${EXE_NAME})
add_test(NAME ${E_SCREEN_APP} COMMAND ${CMAKE_INSTALL_BINDIR}/${E_SCREEN_APP})