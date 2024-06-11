file(GLOB SYTHER_SRC *.cpp)

add_library(Synthesizer STATIC ${SYTHER_SRC})
target_include_directories(Synthesizer PUBLIC ${IFACE_INCLUDE_DIR})

install(TARGETS Synthesizer
        EXPORT MHTRSynthesizerTargets
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        INCLUDES DESTINATION include)

install(DIRECTORY ${MHTR_INCLUDE_DIR}/Synther
DESTINATION include/MHTR)

install(EXPORT MHTRSynthesizerTargets
        FILE MHTRSynthesizerTargets.cmake
        NAMESPACE MHTR::
        DESTINATION lib/cmake/MHTR)
