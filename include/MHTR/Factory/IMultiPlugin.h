#pragma once

#include <vector>
#include <memory>
#include <MHTR/Plugin/IPlugin.h>

namespace MHTR {
    class IMultiPluginFactory {
    public:
        virtual ~IMultiPluginFactory() {}
        virtual std::vector<std::unique_ptr<IPlugin>> CreatePlugins() = 0;
    };
}