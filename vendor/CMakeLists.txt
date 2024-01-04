add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/cxxopts)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/ThunderByteScan)

add_library(jsoncpp INTERFACE)

target_sources(jsoncpp INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/JSONCPP/dist/jsoncpp.cpp)
target_include_directories(jsoncpp INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/JSONCPP/include)

add_library(capstone INTERFACE)
target_include_directories(capstone INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/CAPSTONE/include)
target_link_libraries(capstone INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/CAPSTONE/capstone.lib)

add_library(threadpool INTERFACE)
target_include_directories(threadpool INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/THREADPOOL/include)