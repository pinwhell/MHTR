file(GLOB MD_SRC *.cpp)

add_library(MetadataHunter STATIC ${MD_SRC})
target_include_directories(MetadataHunter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)