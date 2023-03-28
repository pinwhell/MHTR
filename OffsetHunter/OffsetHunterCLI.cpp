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
        /* ("b,bar", "Param bar", cxxopts::value<std::string>()->default_value("This is the default"))
         ("d,debug", "Enable debugging", cxxopts::value<bool>()->default_value("false"))
         ("f,foo", "Param foo", cxxopts::value<int>()->default_value("10"))
         */

         // Brief so easily reference to add anything in the future
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
        dumper->Run();

    return 0;
}
