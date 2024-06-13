#pragma once

#include <string>
#include <filesystem>
#include <MHTR/Factory/IMultiPlugin.h>

namespace MHTR {
    class FromPluginFolderMultiPluginFactory : public IMultiPluginFactory {
    public:
        FromPluginFolderMultiPluginFactory(const std::string& pluginDirPath, int argc = 0, const char* argv[] = nullptr);
        FromPluginFolderMultiPluginFactory(const std::filesystem::path& pluginDirPath, int argc = 0, const char* argv[] = nullptr);

        MultiPluginInstance CreatePlugins() override;

        std::string mPluginDirPath;
        int mArgc;
        const char** mArgv;
    };
}