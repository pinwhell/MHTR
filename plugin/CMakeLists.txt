###############
#  Plugin SDK #
###############

add_library(MHTRPluginSDK STATIC PluginSDK.cpp)
target_link_libraries(MHTRPluginSDK PRIVATE Metadata MetadataSynthers)
target_include_directories(MHTRPluginSDK PUBLIC $<BUILD_INTERFACE:${INCLUDE_DIR}> $<INSTALL_INTERFACE:include>)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT}/plugins)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BIN_OUTPUT}/plugins)

###############
#	Plugins	  #
###############

add_library(HPPRTReportPlugin SHARED HPPRTReportPlugin.cpp)
target_link_libraries(HPPRTReportPlugin MHTRPluginSDK cxxopts)

install(TARGETS MHTRPluginSDK
        EXPORT MHTRPluginSDKTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)

install(DIRECTORY ${MHTR_INCLUDE_DIR}/Plugin
        DESTINATION include/MHTR)

install(EXPORT MHTRPluginSDKTargets
        FILE MHTRPluginSDKTargets.cmake
        NAMESPACE MHTR::
        DESTINATION lib/cmake/MHTR)