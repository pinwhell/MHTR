#include "ConfigManager.h"
#include <filesystem>
#include "FileHelper.h"

namespace fs = std::filesystem;

void ConfigManager::setConfigPath(const std::string& path)
{
	mConfigPath = path;
}

std::string ConfigManager::getDumpTargetPath()
{
	return mDumpTargetPath;
}

std::string ConfigManager::getMainCategoryName()
{
	return  mMainCategory;
}

std::string ConfigManager::getHppOutputPath()
{
	return mHppOutputPath;
}

bool ConfigManager::Init()
{
	if (FileHelper::IsValidFilePath(mConfigPath, true, true) == false)
		return false;

	if (JsonHelper::File2Json(mConfigPath, mConfigRoot) == false)
		return false;

	if (JSON_ASSERT_STR_EMPTY(mConfigRoot, "dump_targets_path") == false)
	{
		printf("\"%s\", Invalid \"dump_targets_path\" or empty\n", mConfigPath.c_str());
		return false;
	}

	mDumpTargetPath = mConfigRoot.get<std::string>("dump_targets_path", "");

	if (FileHelper::IsValidFilePath(mDumpTargetPath, true, true) == false)
		return false;

	mOutputName = mConfigRoot.get<std::string>("output_name", "Output");
	mMainCategory = mConfigRoot.get<std::string>("main_category", "Main");
	mHppOutputPath = mConfigRoot.get<std::string>("hpp_output_path", mOutputName + ".hpp");

	return true;
}
