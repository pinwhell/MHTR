#pragma once

#include <memory>
#include "CapstoneHelperProvider.h"
#include "ConfigManager.h"
#include "TargetManager.h"

class OffsetHunter
{
private:

	std::unique_ptr<ConfigManager> mConfigManager;
	std::unique_ptr<CapstoneHelperProvider> mCapstoneHelperProvider;
	std::unique_ptr<TargetManager> mTargetManager;

public:
	OffsetHunter();

	bool Init();
	void Run();

	void ComputeAll();
	void SaveResults();

	void setConfigPath(const std::string& path);

	CapstoneHelperProvider* getCapstoneHelperProvider();
	ConfigManager* getConfigManager();
};

