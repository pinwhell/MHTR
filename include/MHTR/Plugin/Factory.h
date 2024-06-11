#pragma once

#include <memory>
#include <MHTR/Library.h>
#include <MHTR/Plugin/IPlugin.h>

class PluginFactory {
public:
    PluginFactory(Library&& lib);

    std::unique_ptr<IPlugin> CreatePlugin();

    Library mLibrary;
    CreatePluginFn mCreatePluginFn;
};