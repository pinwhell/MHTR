add_definitions(-DMHR_SAMPLES_DIR="${CMAKE_SOURCE_DIR}/samples")

file(GLOB MHR_TESTS_SRCS *.cpp)

foreach(MHR_TEST_SRC ${MHR_TESTS_SRCS})
	get_filename_component(MHR_TEST_NAME ${MHR_TEST_SRC} NAME_WE)
	add_executable(${MHR_TEST_NAME} ${MHR_TEST_SRC})
	target_link_libraries(${MHR_TEST_NAME} MetadataHunter doctest_with_main)
endforeach()

add_executable(MetadataAndGeneralTests MetadataAndGeneralTests.cxx)
target_link_libraries(MetadataAndGeneralTests MetadataHunter)

#####################
#	   CLI Test		#
#####################


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT}/test/cli)

add_executable(CLITest CLITest.cxx ${CMAKE_CURRENT_SOURCE_DIR}/../src/CLI/MH.cpp)
target_link_libraries(CLITest MetadataHunter BSThreadPool cxxopts)


#####################
#	 Plugin Test	#
#####################


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BIN_OUTPUT}/test/cli/plugins)

add_library(SamplePlugin SHARED SamplePlugin.cxx)

target_link_libraries(SamplePlugin MHTRPluginSDK)