file(GLOB_RECURSE MD_SRC *.cpp)

list(FILTER MD_SRC EXCLUDE REGEX "CLI/")
list(FILTER MD_SRC EXCLUDE REGEX "File/")
list(FILTER MD_SRC EXCLUDE REGEX "Synther/")
list(FILTER MD_SRC EXCLUDE REGEX "Metadata/")

add_subdirectory(File)
add_subdirectory(Synther)
add_subdirectory(Metadata)

add_library(MetadataHunter STATIC ${MD_SRC})
target_compile_features(MetadataHunter PUBLIC cxx_std_20)
target_include_directories(MetadataHunter PUBLIC ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(MetadataHunter Metadata MetadataLookups MetadataSynthers tbs::tbs nlohmann_json::nlohmann_json cstone::cstone elfpp::elfpp File Synthesizer)

add_subdirectory(CLI)
