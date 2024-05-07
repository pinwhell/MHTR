cmake_minimum_required(VERSION 3.15)

project (MetadataHunter)

option(BUILD_TESTS "Build tests" ON)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(vendor)
add_subdirectory(src)

if(BUILD_TESTS)
	add_subdirectory(tests)
endif()