#include "OffsetHunter.h"
#include <iostream>
#include <cxxopts.hpp>

OffsetHunter::OffsetHunter()
{
    mCapstoneHelperProvider = std::make_unique<CapstoneHelperProvider>();
    mTargetManager = std::make_unique<TargetManager>();
    mConfigManager = std::make_unique<ConfigManager>();
}

bool OffsetHunter::Init()
{
    if (mConfigManager->Init() == false)
        return false;

    mTargetManager->setDumpTargetPath(mConfigManager->getDumpTargetPath());

    if (mTargetManager->Init() == false)
        return false;

    return true;
}

void OffsetHunter::Run()
{
    ComputeAll();
}

void OffsetHunter::ComputeAll()
{
    mTargetManager->ComputeAll();
}

void OffsetHunter::setConfigPath(const std::string& path)
{
    mConfigManager->setConfigPath(path);
}

CapstoneHelperProvider* OffsetHunter::getCapstoneHelperProvider()
{
    return mCapstoneHelperProvider.get();
}
