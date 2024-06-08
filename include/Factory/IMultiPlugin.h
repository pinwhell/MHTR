#pragma once

#include <vector>
#include <memory>
#include <Plugin/IPlugin.h>

class IMultiPluginFactory {
public:
    virtual ~IMultiPluginFactory() {}
    virtual std::vector<std::unique_ptr<IPlugin>> CreatePlugins() = 0;
};