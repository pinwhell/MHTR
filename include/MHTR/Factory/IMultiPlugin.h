#pragma once

#include <vector>
#include <memory>
#include <MHTR/Plugin/IPlugin.h>

namespace MHTR {
    using PluginInstance = typename std::unique_ptr<IPlugin>;
    using MultiPluginInstance = std::vector<PluginInstance>;

    class IMultiPluginFactory {
    public:
        virtual ~IMultiPluginFactory() {}
        virtual MultiPluginInstance CreatePlugins() = 0;
    };
}