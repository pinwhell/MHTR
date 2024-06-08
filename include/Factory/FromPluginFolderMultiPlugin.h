#pragma once

#include <string>
#include <filesystem>
#include <Factory/IMultiPlugin.h>

class FromPluginFolderMultiPluginFactory : public IMultiPluginFactory {
public:
    FromPluginFolderMultiPluginFactory(const std::string& pluginDirPath, int argc = 0, const char* argv[] = nullptr);
    FromPluginFolderMultiPluginFactory(const std::filesystem::path& pluginDirPath, int argc = 0, const char* argv[] = nullptr);

    std::vector<std::unique_ptr<IPlugin>> CreatePlugins() override;

    std::string mPluginDirPath;
    int mArgc;
    const char** mArgv;
};