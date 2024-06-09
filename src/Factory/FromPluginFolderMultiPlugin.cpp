#include <Factory/FromPluginFolderMultiPlugin.h>
#include <Plugin/Factory.h>
#include <unordered_set>
#include <Pltform.h>

FromPluginFolderMultiPluginFactory::FromPluginFolderMultiPluginFactory(const std::string& pluginDirPath, int argc, const char* argv[])
    : mPluginDirPath(std::filesystem::absolute(pluginDirPath).string())
    , mArgc(argc)
    , mArgv(argv)
{}

FromPluginFolderMultiPluginFactory::FromPluginFolderMultiPluginFactory(const std::filesystem::path& pluginDirPath, int argc, const char* argv[])
    : FromPluginFolderMultiPluginFactory(pluginDirPath.string(), argc, argv)
{}

std::vector<std::unique_ptr<IPlugin>> FromPluginFolderMultiPluginFactory::CreatePlugins()
{
    std::vector<std::unique_ptr<IPlugin>> result;
    std::unordered_set<std::filesystem::path> loadedLibs;
    std::unordered_set<std::string> loadedPlugins;

    for (std::filesystem::path currFile : std::filesystem::directory_iterator(mPluginDirPath))
    {
        if ((currFile.extension() == WIN_LINUX(".dll", ".so")) == false)
            continue;

        // At this point, this is an actual module ...

        if (loadedLibs.count(currFile.filename()))
            continue;

        // At this point, a plugin with this file-name hasnt been loaded yet ...

        loadedLibs.insert(currFile.filename());

        std::unique_ptr<IPlugin> thisPlugin = PluginFactory(Library::Load(currFile.string().c_str())).CreatePlugin();
        std::string thisPluginName = thisPlugin->GetName();

        if (loadedPlugins.count(thisPluginName))
            continue;

        // At this point, the actual plugin hasnt been loaded ...

        try { thisPlugin->Init(mArgc, mArgv); } // Lets try and initilize it ...
        catch (...)
        {
            continue;
        }

        // At this point, we succesfully initialized it ...

        loadedPlugins.insert(thisPluginName);
        result.emplace_back(std::move(thisPlugin));
    }

    return result;
}
