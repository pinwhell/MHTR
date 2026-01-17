@PACKAGE_INIT@

include(${CMAKE_CURRENT_LIST_DIR}/MHTRPluginMetadataTargets.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/MHTRPluginSDKTargets.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/MHTRSynthesizerTargets.cmake)

set(MHTR_INCLUDES ${CMAKE_INSTALL_PREFIX}/include)
set(MHTR_FOUND TRUE)
