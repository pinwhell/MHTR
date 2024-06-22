###############
#  Plugin SDK #
###############

add_library(MHTRPluginSDK STATIC PluginSDK.cpp)
target_compile_features(MHTRPluginSDK INTERFACE cxx_std_17)
target_link_libraries(MHTRPluginSDK Metadata cxxopts)
target_include_directories(MHTRPluginSDK PUBLIC $<BUILD_INTERFACE:${INCLUDE_DIR}> $<INSTALL_INTERFACE:include>)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT}/plugins)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BIN_OUTPUT}/plugins)

###############
#	Plugins	  #
###############

target_sources(MetadataHunter PUBLIC HPPRTReportPlugin.cpp)
target_link_libraries(MetadataHunter cxxopts)

install(TARGETS MHTRPluginSDK
        EXPORT MHTRPluginSDKTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)

install(EXPORT MHTRPluginSDKTargets
        FILE MHTRPluginSDKTargets.cmake
        NAMESPACE MHTR::
        DESTINATION lib/cmake/MHTR)