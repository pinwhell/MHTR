add_library(Metadata STATIC Metadata.cpp Target.cpp Result.cpp Utility.cpp)
target_include_directories(Metadata PUBLIC ${IFACE_INCLUDE_DIR})

add_library(MetadataLookups INTERFACE)
target_sources(MetadataLookups INTERFACE Lookups.cpp)
target_compile_features(MetadataLookups INTERFACE cxx_std_20)
target_link_libraries(MetadataLookups INTERFACE tbs::tbs cstone::cstone)

add_library(MetadataSynthers STATIC Synthers.cpp)
target_compile_features(MetadataSynthers PUBLIC cxx_std_20)
target_link_libraries(MetadataSynthers PUBLIC Synthesizer Metadata)
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