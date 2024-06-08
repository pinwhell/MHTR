#include <Plugin/Factory.h>

PluginFactory::PluginFactory(Library&& lib)
    : mLibrary(std::move(lib))
    , mCreatePluginFn((CreatePluginFn)nullptr)
{}

std::unique_ptr<IPlugin> PluginFactory::CreatePlugin()
{
    if (!mCreatePluginFn)
        mCreatePluginFn = mLibrary.GetSymbol<CreatePluginFn>("CreatePlugin");

    return std::unique_ptr<IPlugin>(mCreatePluginFn());
}
