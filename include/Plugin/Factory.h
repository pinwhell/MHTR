#pragma once

#include <memory>
#include <Library.h>
#include <Plugin/IPlugin.h>

class PluginFactory {
public:
    PluginFactory(Library&& lib);

    std::unique_ptr<IPlugin> CreatePlugin();

    Library mLibrary;
    CreatePluginFn mCreatePluginFn;
};