add_subdirectory(CStone)

add_subdirectory(cxxopts)
add_subdirectory(ELFPP)
add_subdirectory(json)

set (TBS_MT OFF)
add_subdirectory(TBS)

add_library(BSThreadPool INTERFACE)
target_include_directories(BSThreadPool INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/thread-pool/include)