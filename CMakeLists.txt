cmake_minimum_required(VERSION 3.15)

project (MHTR)

option(USE_STATIC_LINKING "Use static linking for the runtime" ON)

if (USE_STATIC_LINKING)
    if (MSVC)
        # MSVC specific static linking flag
        add_compile_options(/MT$<$<CONFIG:Debug>:d>)
    else()
        # GCC/Clang specific static linking flag
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    endif()
endif()


include(cmake/CBuildKit.cmake)

add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
option(BUILD_TESTS "Build tests" ON)

set(CMAKE_CXX_STANDARD 17)

include(cmake/BuildHelper.cmake)
include(cmake/PlatformInfo.cmake)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BIN_OUTPUT})
set(CMAKE_PDB_OUTPUT_DIRECTORY ${BIN_OUTPUT})
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(IFACE_INCLUDE_DIR $<BUILD_INTERFACE:${INCLUDE_DIR}> $<INSTALL_INTERFACE:include>)
set(MHTR_INCLUDE_DIR ${INCLUDE_DIR}/MHTR)


add_subdirectory(vendor)
add_subdirectory(src)
add_subdirectory(plugin)

if(BUILD_TESTS)
	add_subdirectory(tests)
endif()

#####################
#	Export Targets	#
#####################

install(DIRECTORY ${MHTR_INCLUDE_DIR} 
DESTINATION include)

configure_file(cmake/MHTRConfig.in.cmake ${CMAKE_CURRENT_BINARY_DIR}/MHTRConfig.cmake @ONLY)

install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/MHTRConfig.cmake
        DESTINATION lib/cmake/MHTR)