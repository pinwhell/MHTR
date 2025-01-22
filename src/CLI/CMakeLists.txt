add_executable(MHCLI main.cpp MH.cpp)
find_package(cxxopts REQUIRED)

target_link_libraries(MHCLI MetadataHunter cxxopts::cxxopts BSThreadPool)