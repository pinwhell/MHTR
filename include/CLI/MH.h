#pragma once

#include <Storage.h>
#include <cxxopts.hpp>
#include <Factory/MetadataTarget.h>
#include <Factory/IMultiPlugin.h>
#include <Provider/IProvider.h>
#include <Binary/IBinary.h>

class MHCLI {
public:
    MHCLI(int argc, const char* argv[], IMultiPluginFactory* multiPluginFactory = nullptr);

    int Run();

    cxxopts::Options mCLIOptions;
    cxxopts::ParseResult mCLIParseRes;
    MetadataTargetFactory mMetadataTargetProvider;
    Storage<std::unique_ptr<IProvider>> mProvidersStorage;
    Storage<std::unique_ptr<ICapstoneProvider>> mCStoneProvidersStorage;
    Storage<std::unique_ptr<IBinary>> mBinariesStorage;
    IMultiPluginFactory* mAllPluginsFactory;
    std::vector<std::unique_ptr<IPlugin>> mAllPlugins;
};