file(GLOB_RECURSE MD_SRC *.cpp)

list(FILTER MD_SRC EXCLUDE REGEX "CLI/")
list(FILTER MD_SRC EXCLUDE REGEX "File/")
list(FILTER MD_SRC EXCLUDE REGEX "Synther/")

add_subdirectory(File)
add_subdirectory(Synther)

add_library(MetadataHunter STATIC ${MD_SRC})
target_include_directories(MetadataHunter PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(MetadataHunter TBS nlohmann_json fmt CStone ELFPP File Synthesizer)

add_subdirectory(CLI)
