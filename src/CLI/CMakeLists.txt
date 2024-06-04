add_executable(MHCLI main.cpp)

target_link_libraries(MHCLI MetadataHunter cxxopts BSThreadPool)