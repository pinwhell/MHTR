set (TBS_MT OFF)
set(TBS_USE_SSE2 OFF)
set(TBS_USE_AVX OFF)
add_subdirectory(TBS)

add_library(BSThreadPool INTERFACE)
target_include_directories(BSThreadPool INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/thread-pool/include)