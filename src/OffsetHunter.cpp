#include <iostream>
#include <stdlib.h>
#include <OH/OffsetHunter.h>
#include <OH/RandManager.h>
#include <filesystem>

OffsetHunter::OffsetHunter()
{
    mCapstoneHelperProvider = std::make_unique<CapstoneHelperProvider>();
    mTargetManager = std::make_unique<TargetManager>();
    mConfigManager = std::make_unique<ConfigManager>();

    mTargetManager->setParent(this);
}

bool OffsetHunter::Init()
{
    if (mConfigManager->Init() == false)
        return false;

    mTargetManager->setDumpTargetPath(mConfigManager->getDumpTargetPath());
    mTargetManager->setMainCategoryName(mConfigManager->getMainCategoryName());
    mTargetManager->setHppOutputPath(mConfigManager->getHppOutputPath());
    mTargetManager->setDumpDynamic(mConfigManager->getDumpDynamic());
    mTargetManager->setDumpJsonLibName(mConfigManager->getDumpJsonLibName());
    mTargetManager->setDeclareGlobalDumpObj(mConfigManager->getDeclareGlobalDumpObj());
    mTargetManager->setGlobalDumpObjectName(mConfigManager->getGlobalDumpObjectName());
    mTargetManager->setObfuscationBookPath(mConfigManager->getObfuscationBookPath());
    mTargetManager->setObfuscationBookMutationEnabled(mConfigManager->getObfuscationBookMutationEnabled());

    if (mTargetManager->Init() == false)
        return false;

    return true;
}

void OffsetHunter::Run()
{
    ComputeAll();
    SaveResults();
}

void OffsetHunter::ComputeAll()
{
    mTargetManager->ComputeAll();
}

void OffsetHunter::SaveResults()
{
    mTargetManager->SaveResults();
}

void OffsetHunter::setConfigPath(const std::string& path)
{
    const auto absCfgPath = std::filesystem::absolute(path);
    const auto parentPath = absCfgPath.parent_path();

    std::filesystem::current_path(parentPath);

    mConfigManager->setConfigPath(absCfgPath.string());
}

CapstoneHelperProvider* OffsetHunter::getCapstoneHelperProvider()
{
    return mCapstoneHelperProvider.get();
}

ConfigManager* OffsetHunter::getConfigManager()
{
    return mConfigManager.get();
}
