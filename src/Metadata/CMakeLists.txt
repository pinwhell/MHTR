add_library(Metadata INTERFACE)
target_sources(Metadata INTERFACE Metadata.cpp Target.cpp Result.cpp)

add_library(MetadataLookups INTERFACE)
target_sources(MetadataLookups INTERFACE Lookups.cpp)
target_link_libraries(MetadataLookups INTERFACE TBS fmt CStone)

add_library(MetadataSynthers INTERFACE)
target_sources(MetadataSynthers INTERFACE Synthers.cpp)
target_link_libraries(MetadataSynthers INTERFACE fmt Synthesizer)