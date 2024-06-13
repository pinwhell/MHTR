@PACKAGE_INIT@

include(${CMAKE_CURRENT_LIST_DIR}/MHTRPluginMetadataTargets.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/MHTRPluginSDKTargets.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/MHTRSynthesizerTargets.cmake)

find_package(fmt REQUIRED PATHS ${CMAKE_CURRENT_LIST_DIR}/../fmt)
find_package(cxxopts REQUIRED PATHS ${CMAKE_INSTALL_PREFIX}/share/cmake)

set(MHTR_INCLUDES ${CMAKE_INSTALL_PREFIX}/include)
set(MHTR_FOUND TRUE)
