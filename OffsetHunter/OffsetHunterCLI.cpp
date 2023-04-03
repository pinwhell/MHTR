#include "OffsetHunterCLI.h"
#include "OffsetHunter.h"
#include <cxxopts.hpp>
#include <iostream>

int OffsetHunterCLI::Run(int argc, const char** argv)
{
    std::unique_ptr<OffsetHunter> dumper = std::make_unique<OffsetHunter>();
    cxxopts::Options options("Offset Hunter", "Robust Offset Dumper System");

    options.allow_unrecognised_options();

    options.add_options()
        ("h,help", "Print usage")
        ("c,config", "Input Config Json path", cxxopts::value<std::string>())
        ;

    cxxopts::ParseResult args = options.parse(argc, argv);

    if (args.count("help") != 0 || args.count("config") != 1)
    {
        std::cout << options.help() << std::endl;
        return 0;
    }

    std::string configPath = args["config"].as<std::string>();

    dumper->setConfigPath(configPath);

    if (dumper->Init())
    {
        dumper->Run();
        std::cout << "Dumper Finished!\n";
    }

    return 0;
}
