set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT}/plugins)

###############
#	Plugins	  #
###############

add_library(HPPRTReportPlugin SHARED HPPRTReportPlugin.cpp)
target_link_libraries(HPPRTReportPlugin MetadataHunter cxxopts)