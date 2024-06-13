add_library(Metadata STATIC Metadata.cpp Target.cpp Result.cpp Utility.cpp)
target_include_directories(Metadata PUBLIC ${IFACE_INCLUDE_DIR})

add_library(MetadataLookups INTERFACE)
target_sources(MetadataLookups INTERFACE Lookups.cpp)
target_link_libraries(MetadataLookups INTERFACE TBS fmt CStone)

add_library(MetadataSynthers STATIC Synthers.cpp)
target_link_libraries(MetadataSynthers PUBLIC Synthesizer PRIVATE fmt)
target_include_directories(MetadataSynthers PUBLIC ${IFACE_INCLUDE_DIR})


install(TARGETS Metadata MetadataSynthers
        EXPORT MHTRPluginMetadataTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)

install(EXPORT MHTRPluginMetadataTargets
        FILE MHTRPluginMetadataTargets.cmake
        NAMESPACE MHTR::
        DESTINATION lib/cmake/MHTR)