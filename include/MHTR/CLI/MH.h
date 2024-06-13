#pragma once

#include <cxxopts.hpp>
#include <MHTR/Storage.h>
#include <MHTR/Factory/MetadataTarget.h>
#include <MHTR/Factory/IMultiPlugin.h>
#include <MHTR/Provider/IProvider.h>
#include <MHTR/Binary/IBinary.h>

namespace MHTR {
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
        MultiPluginInstance mAllPlugins;
    };
}