cmake_minimum_required(VERSION 3.5)


set(CMAKE_GENERATOR "Ninja")

set(PROGRAM_NAME myabc)

project(svc_host)

enable_testing()

if (MSVC)
    # warning level 4
    add_link_options(/subsystem:console)
    add_compile_options(/W4)
    add_compile_options(/utf-8)
    add_compile_options(/Zi)
    add_compile_options(/MT)
    add_compile_options(/EHsc)
    add_compile_options(/Oy-)
    add_compile_options(/Ob0)
endif()


add_executable(${PROGRAM_NAME} WIN32 main.c)

set_property(TARGET ${PROGRAM_NAME} PROPERTY C_STANDARD 11)
set_property(TARGET ${PROGRAM_NAME} PROPERTY C_STANDARD_REQUIRED ON)

target_include_directories(${PROGRAM_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_sources(${PROGRAM_NAME}
    PRIVATE
    src/formatter.c
    src/string.c
    src/OSInfo.c
    src/server.c
    src/winapi_funcs.c
    src/resource_monitor.c
    src/keyboard_hook.c
    src/curlhelper.c
    src/proxy.c
    src/thutil.c
    src/myzip.c
    src/file_util.c)

set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/${PROGRAM_NAME}_out" CACHE PATH "" FORCE)

include(FetchContent)

set(FETCHCONTENT_BASE_DIR ${CMAKE_BINARY_DIR}/dependencies)

FetchContent_Declare(
    zlib
    URL https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
    SOURCE_DIR ${FETCHCONTENT_BASE_DIR}/zlib
    BINARY_DIR ${FETCHCONTENT_BASE_DIR}/zlib_build

)

FetchContent_MakeAvailable(zlib)


set(ZLIB_INCLUDE_DIR "${zlib_SOURCE_DIR}" "${zlib_BINARY_DIR}" CACHE PATH "" FORCE)

find_library(libz_var zlib NAMES zlibd libz zlib HINTS ${zlib_BINARY_DIR})

if (libz_var)
    set(ZLIB_LIBRARY ${libz_var})
    target_link_libraries(${PROGRAM_NAME} PRIVATE ${libz_var})
endif()

find_package(OpenSSL REQUIRED)

FetchContent_Declare(
    libcurl
    GIT_REPOSITORY https://github.com/curl/curl.git
    GIT_TAG        57495c64871d18905a0941db9196ef90bafe9a29
    SOURCE_DIR ${FETCHCONTENT_BASE_DIR}/curl
    BINARY_DIR ${FETCHCONTENT_BASE_DIR}/curl_out
)

set(CURL_USE_LIBPSL     OFF)
set(CURL_USE_LIBIDN2    OFF)
set(CURL_USE_LIBSSH2    OFF)
set(USE_LIBIDN2         OFF)
set(BUILD_EXAMPLES      OFF)
set(CURL_USE_LIBUV      OFF)
set(BUILD_TESTING       OFF)
set(HAVE_ZSTD           OFF)
set(CURL_ZLIB           ON)
set(CURL_USE_OPENSSL    ON)
set(BUILD_LIBCURL_DOCS  OFF)
set(BUILD_MISC_DOCS     OFF)

set(CMAKE_DEBUG_POSTFIX "" CACHE STRING "" FORCE)
set(IMPORT_LIB_SUFFIX "" CACHE STRING "" FORCE)
set(CMAKE_STATIC_LIBRARY_SUFFIX .lib CACHE STRING "" FORCE)

FetchContent_MakeAvailable(libcurl)


set(CURL_INCLUDE_DIR "${libcurl_SOURCE_DIR}/include" CACHE PATH "" FORCE)
target_include_directories(${PROGRAM_NAME} PRIVATE ${CURL_INCLUDE_DIR})
target_include_directories(${PROGRAM_NAME} PRIVATE ${ZLIB_INCLUDE_DIR})
target_link_libraries(${PROGRAM_NAME} PRIVATE CURL::libcurl)


FetchContent_Declare(
    cjson
    URL https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.tar.gz
    SOURCE_DIR ${FETCHCONTENT_BASE_DIR}/cjson
    BINARY_DIR ${FETCHCONTENT_BASE_DIR}/cjson_out
)

FetchContent_MakeAvailable(cjson)


set(CJSON_INCLUDE_DIR ${cjson_SOURCE_DIR} CACHE PATH "" FORCE)

target_include_directories(${PROGRAM_NAME} PRIVATE ${CJSON_INCLUDE_DIR})

target_link_libraries(${PROGRAM_NAME} PRIVATE cjson)


FetchContent_Declare(
    libevent
    URL     https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz
    SOURCE_DIR ${FETCHCONTENT_BASE_DIR}/libevent_src
    BINARY_DIR ${FETCHCONTENT_BASE_DIR}/libevent_bin
)


set(EVENT__DISABLE_OPENSSL ON)
FetchContent_MakeAvailable(libevent)


# include libevent dirs

set(libevent_include "${libevent_SOURCE_DIR}/include")
target_include_directories(${PROGRAM_NAME} PRIVATE ${libevent_include})

# link eventlib libraries

target_link_libraries(${PROGRAM_NAME} PRIVATE event)



FetchContent_Declare(
    brotli
    GIT_REPOSITORY https://github.com/google/brotli
    GIT_TAG ed738e842d2fbdf2d6459e39267a633c4a9b2f5d
    SOURCE_DIR ${FETCHCONTENT_BASE_DIR}/brotli_src
    BINARY_DIR ${FETCHCONTENT_BASE_DIR}/brotli_bin
)

FetchContent_MakeAvailable(brotli)

target_link_libraries(${PROGRAM_NAME} PRIVATE ${BROTLI_LIBRARIES})
target_include_directories(${PROGRAM_NAME} PRIVATE ${BROTLI_INCLUDE_DIRS})
# install 

set (CMAKE_INSTALL_BINDIR ${CMAKE_INSTALL_PREFIX}/bin)
message(STATUS "Install binary prefix: ${CMAKE_INSTALL_BINDIR}")
install(TARGETS cjson)
install(TARGETS RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static)
install(TARGETS ${PROGRAM_NAME})

install(FILES $<TARGET_RUNTIME_DLLS:${PROGRAM_NAME}> TYPE BIN)


add_subdirectory(tests/)