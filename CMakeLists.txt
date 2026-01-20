cmake_minimum_required(VERSION 3.16)
project(substagent VERSION 0.1 LANGUAGES C)

set(BUILD_INFO_IN  "${CMAKE_CURRENT_SOURCE_DIR}/src/build_info.h.in")
set(BUILD_INFO_OUT "${CMAKE_CURRENT_BINARY_DIR}/build_info.h")

add_custom_target(build_info ALL
    COMMAND "${CMAKE_COMMAND}"
            -DSRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
            -P "${CMAKE_SOURCE_DIR}/cmake/gen_build_info.cmake"
    BYPRODUCTS "${BUILD_INFO_OUT}"
    COMMENT "Generating build_info.h with current git hash"
)

find_package(JNI REQUIRED)

add_library(substagent SHARED src/substagent.c src/fis_hook.c src/utils.c)
add_library(stb INTERFACE)

target_include_directories(stb INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/external/stb)
target_include_directories(substagent PRIVATE ${JNI_INCLUDE_DIRS})
target_include_directories(substagent PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(substagent PRIVATE stb)