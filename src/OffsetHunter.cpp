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

    mTargetManager->setConfigManager(mConfigManager.get());

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

    mConfigManager->mConfigPath = absCfgPath.string();
}

CapstoneHelperProvider* OffsetHunter::getCapstoneHelperProvider()
{
    return mCapstoneHelperProvider.get();
}

ConfigManager* OffsetHunter::getConfigManager()
{
    return mConfigManager.get();
}
