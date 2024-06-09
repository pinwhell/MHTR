###############
#  PluginSDK  #
###############

add_library(MHTRPluginSDK STATIC)
target_link_libraries(MHTRPluginSDK PUBLIC Metadata MetadataSynthers)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT}/plugins)

###############
#	Plugins	  #
###############

add_library(HPPRTReportPlugin SHARED HPPRTReportPlugin.cpp)
target_link_libraries(HPPRTReportPlugin MHTRPluginSDK cxxopts)