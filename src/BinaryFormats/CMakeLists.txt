add_library(BinaryFormats INTERFACE)

file(GLOB BIN_FMT_SRC *.cpp)

target_sources(BinaryFormats INTERFACE ${BIN_FMT_SRC})