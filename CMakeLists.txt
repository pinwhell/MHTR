cmake_minimum_required(VERSION 3.15)

project (MetadataHunter)

option(BUILD_TESTS "Build tests" ON)

set(CMAKE_CXX_STANDARD 17)

include(cmake/build_helper.cmake)
include(cmake/platform_info.cmake)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT})
set(CMAKE_PDB_OUTPUT_DIRECTORY ${BIN_OUTPUT})
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_subdirectory(vendor)
add_subdirectory(src)

if(BUILD_TESTS)
	add_subdirectory(tests)
endif()