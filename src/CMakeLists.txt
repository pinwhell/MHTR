file(GLOB_RECURSE MD_SRC *.cpp)

add_library(MetadataHunter STATIC ${MD_SRC})
target_include_directories(MetadataHunter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(MetadataHunter PUBLIC TBS nlohmann_json fmt CStone ELFPP)