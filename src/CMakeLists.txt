file(GLOB_RECURSE MD_SRC *.cpp)

list(FILTER MD_SRC EXCLUDE REGEX "CLI/")
list(FILTER MD_SRC EXCLUDE REGEX "File/")
list(FILTER MD_SRC EXCLUDE REGEX "Synther/")
list(FILTER MD_SRC EXCLUDE REGEX "Metadata/")

add_subdirectory(File)
add_subdirectory(Synther)
add_subdirectory(Metadata)

find_package(nlohmann_json REQUIRED)
find_package(fmt REQUIRED)
find_package(CStone REQUIRED)
find_package(ELFPP REQUIRED)

add_library(MetadataHunter STATIC ${MD_SRC})
target_include_directories(MetadataHunter PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(MetadataHunter Metadata MetadataLookups MetadataSynthers TBS nlohmann_json::nlohmann_json fmt::fmt cstone::cstone elfpp::elfpp File Synthesizer)

add_subdirectory(CLI)
