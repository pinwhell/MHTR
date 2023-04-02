#pragma once

#include <string>
#include <json/json.h>
#include "JsonValueWrapper.h"

class ConfigManager
{
public:
	std::string mConfigPath;
	JsonValueWrapper mConfigRoot;

	std::string mMainCategory;
	std::string mOutputName;
	std::string mDumpTargetPath;
	std::string mHppOutputPath;

public:
	void setConfigPath(const std::string& path);

	std::string getDumpTargetPath();
	std::string getMainCategoryName();
	std::string getHppOutputPath();

	bool Init();
};