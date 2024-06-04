add_executable(MHCLI main.cpp "MH.cpp")

target_link_libraries(MHCLI MetadataHunter cxxopts BSThreadPool)