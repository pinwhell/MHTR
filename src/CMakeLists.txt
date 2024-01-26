add_subdirectory(BinaryFormats)

file(GLOB OH_SRCS *.cpp)

add_library(OffsetHunter STATIC ${OH_SRCS})

target_include_directories(OffsetHunter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(OffsetHunter PUBLIC jsoncpp capstone ThunderByteScan threadpool BinaryFormats)

add_subdirectory(CLI)