file(GLOB_RECURSE MD_SRC *.cpp)

list(FILTER MD_SRC EXCLUDE REGEX "CLI/")

add_library(MetadataHunter STATIC ${MD_SRC})
target_include_directories(MetadataHunter PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(MetadataHunter TBS nlohmann_json fmt CStone ELFPP)

add_subdirectory(CLI)
