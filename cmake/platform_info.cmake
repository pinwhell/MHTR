if(WIN32 OR MSVC)
	add_compile_definitions(WINDOWS)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
	add_compile_definitions(LINUX)
endif()
	