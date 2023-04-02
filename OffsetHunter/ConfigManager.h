#pragma once

#include <string>
#include <json/json.h>
#include "JsonValueWrapper.h"

class ConfigManager
{
public:
	std::string mConfigPath;
	JsonValueWrapper mConfigRoot;

	bool mDumpDynamic;

	std::string mMainCategory;
	std::string mOutputName;
	std::string mDumpTargetPath;
	std::string mHppOutputPath;
	std::string mDumpJsonLibName;
	std::string mGlobalDumpObjName;

	bool mDeclareGlobalDumpObj;

public:
	void setConfigPath(const std::string& path);

	std::string getDumpTargetPath();
	std::string getMainCategoryName();
	std::string getHppOutputPath();
	std::string getDumpJsonLibName();
	std::string getGlobalDumpObjectName();

	bool Init();
	bool InitDynamicDumpInfo();
	bool InitDumpInfo();

	bool getDumpDynamic();
	bool getDeclareGlobalDumpObj();
};