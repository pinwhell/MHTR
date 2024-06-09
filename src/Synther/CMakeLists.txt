file(GLOB SYTHER_SRC *.cpp)

add_library(Synthesizer STATIC ${SYTHER_SRC})
target_include_directories(Synthesizer PUBLIC ${INCLUDE_DIR})
