add_library(File INTERFACE)
target_include_directories(File INTERFACE ${INCLUDE_DIR})
target_sources(File INTERFACE Operation.cpp)