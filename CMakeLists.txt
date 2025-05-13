
cmake_minimum_required(VERSION 3.5)

cmake_policy(SET CMP0074 NEW)

set(CMAKE_GENERATOR "Ninja")




if (LOCAL_ADDRESS)
    set(PROGRAM_NAME XControlAgent_local)
else()
    set(PROGRAM_NAME XControlAgent_remote)
endif()

project(XControlAgent LANGUAGES C)


set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/${PROGRAM_NAME}_out" CACHE PATH "" FORCE)
set(CMAKE_INSTALL_BINDIR ${CMAKE_INSTALL_PREFIX}/bin)

enable_testing()


set_property(GLOBAL PROPERTY C_STANDARD 11)
set_property(GLOBAL PROPERTY C_STANDARD_REQUIRED ON)


if(MSVC)
    
    add_link_options(/subsystem:console)
    add_compile_options(/utf-8)

endif()


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Building ${PROGRAM_NAME} in Debug mode")
    if(MSVC)

        add_compile_options(
            /W4         
            /EHsc    
            /Oy-     
            /Ob0     
        )

    endif()
    add_definitions(-DDEBUG_MODE)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Building ${PROGRAM_NAME} in Release mode")
    if(MSVC)
        add_compile_options(
            /O2    
            /Ob2   
        )
        
    endif()
    add_definitions(-DNDEBUG)
else()
    message(WARNING "Build type not specified. Defaulting to Debug.")
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Choose the type of build." FORCE)
    if(MSVC)
        add_compile_options(/Zi /Od)
        add_link_options(/DEBUG)
    endif()
    add_definitions(-DDEBUG_MODE)
endif()


add_executable(${PROGRAM_NAME} WIN32 main.c)


set_property(TARGET ${PROGRAM_NAME} PROPERTY C_STANDARD 11)
set_property(TARGET ${PROGRAM_NAME} PROPERTY C_STANDARD_REQUIRED ON)


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
        src/file_util.c
)


target_include_directories(${PROGRAM_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")


set(FETCHCONTENT_BASE_DIR ${CMAKE_BINARY_DIR}/dependencies)


include(FetchContent)



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
set(BUILD_LIBCURL_DOCS  OFF)
set(BUILD_MISC_DOCS     OFF)
set(USE_NGHTTP2         OFF)

set(CURL_ZLIB           ON)
set(CURL_USE_OPENSSL    ON)

set(CMAKE_DEBUG_POSTFIX "" CACHE STRING "" FORCE)
set(IMPORT_LIB_SUFFIX "" CACHE STRING "" FORCE)
set(CMAKE_STATIC_LIBRARY_SUFFIX .lib CACHE STRING "" FORCE)
set(CMAKE_SHARED_LIBRARY_SUFFIX .dll CACHE STRING "" FORCE)


find_package(OpenSSL REQUIRED)

if (NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL was not found")
endif()

# zlib
# search the library if ZLIB_ROOT provided
#---

if (ZLIB_ROOT)

    # set common zlib library names
    set(ZLIB_NAMES)
    set(ZLIB_SEARCH_DIRS)

    if (ZLIB_STATIC)
        set(ZLIB_SEARCH_DIRS lib)
    else()
        set(ZLIB_SEARCH_DIRS bin)
    endif()

    

    set(CMAKE_FIND_LIBRARY_SUFFIXES .dll)
    # if static is defined, we search for static
    if (ZLIB_STATIC)
        list(APPEND ZLIB_NAMES zs zlibstatic zstatic)
        set(CMAKE_FIND_LIBRARY_SUFFIXES .lib)
    endif(ZLIB_STATIC)

    list(APPEND ZLIB_NAMES zlib z)

    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        foreach(libname ${ZLIB_NAMES})
            set(dbg_NAME)
            string(APPEND dbg_NAME ${libname} "d")
            list(POP_FRONT ZLIB_NAMES)
            list(APPEND ZLIB_NAMES ${dbg_NAME})
            
        endforeach()
    endif()
    # search for import lib and dll
    if (NOT ZLIB_STATIC)
        message("Configuring shared ZLIB")
        find_library(ZDLL NAMES ${ZLIB_NAMES} HINTS ${ZLIB_ROOT} PATH_SUFFIXES "bin" NO_DEFAULT_PATH)
        set(CMAKE_FIND_LIBRARY_SUFFIXES .lib)
        find_library(ZLIB_LIBRARY NAMES ${ZLIB_NAMES} HINTS ${ZLIB_ROOT} PATH_SUFFIXES "lib" "bin" NO_DEFAULT_PATH)
        
        if (ZDLL AND ZLIB_LIBRARY)
            install(FILES ${ZDLL} DESTINATION bin)
            target_link_libraries(${PROGRAM_NAME} PRIVATE ${ZLIB_LIBRARY})
        endif()
    else()
        message("Configuring static ZLIB")

        find_library(ZLIB_LIBRARY NAMES ${ZLIB_NAMES} HINTS ${ZLIB_ROOT} PATH_SUFFIXES "lib" NO_DEFAULT_PATH)
        if (ZLIB_LIBRARY)
            message("Static zlib: ${ZLIB_LIBRARY}")
            target_link_libraries(${PROGRAM_NAME} PRIVATE ${ZLIB_LIBRARY})
        endif()

    endif()


endif(ZLIB_ROOT)



FetchContent_MakeAvailable(libcurl)




FetchContent_Declare(
    cjson
    URL https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.tar.gz
    SOURCE_DIR ${FETCHCONTENT_BASE_DIR}/cjson
    BINARY_DIR ${FETCHCONTENT_BASE_DIR}/cjson_out
)
FetchContent_MakeAvailable(cjson)


FetchContent_Declare(
    libevent
    URL https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz
    SOURCE_DIR ${FETCHCONTENT_BASE_DIR}/libevent_src
    BINARY_DIR ${FETCHCONTENT_BASE_DIR}/libevent_bin
)


set(EVENT__DISABLE_OPENSSL ON)
set(EVENT__DISABLE_TESTS   ON)
set(EVENT__DISABLE_SAMPLES ON)
set(EVENT__LIBRARY_TYPE STATIC)

FetchContent_MakeAvailable(libevent)


set(CURL_INCLUDE_DIR "${libcurl_SOURCE_DIR}/include" CACHE PATH "" FORCE)
target_include_directories(${PROGRAM_NAME} PRIVATE ${CURL_INCLUDE_DIR})
target_include_directories(${PROGRAM_NAME} PRIVATE ${ZLIB_INCLUDE_DIR})
target_link_libraries(${PROGRAM_NAME} PRIVATE CURL::libcurl)


set(CJSON_INCLUDE_DIR ${cjson_SOURCE_DIR} CACHE PATH "" FORCE)
target_include_directories(${PROGRAM_NAME} PRIVATE ${CJSON_INCLUDE_DIR})
target_link_libraries(${PROGRAM_NAME} PRIVATE cjson)


set(libevent_include "${libevent_SOURCE_DIR}/include")
target_include_directories(${PROGRAM_NAME} PRIVATE ${libevent_include})
target_link_libraries(${PROGRAM_NAME} PRIVATE event)





# macros

if (LOCAL_ADDRESS)
    message("Using local address ...")
    target_compile_definitions(${PROGRAM_NAME} PRIVATE -DUSE_LOCAL)
else()
    message("Using remote address ...")
endif()

install(TARGETS ${PROGRAM_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib/static
)
install(FILES $<TARGET_RUNTIME_DLLS:${PROGRAM_NAME}> TYPE BIN)

add_subdirectory(tests)