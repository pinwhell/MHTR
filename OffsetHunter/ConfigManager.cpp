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
	if (mDumpTargetPath.empty())
	{
		std::string path = mConfigRoot.get<std::string>("dump_targets_path", "");

		if (path.empty())
			abort();

		mDumpTargetPath = path;
	}

	return mDumpTargetPath;
}

std::string ConfigManager::getMainCategoryName()
{
	if (mMainCategory.empty())
		mMainCategory = mConfigRoot.get<std::string>("main_category", "Main");

	return  mMainCategory;
}

std::string ConfigManager::getOutputName()
{
	if (mOutputName.empty())
		mOutputName = mConfigRoot.get<std::string>("output_name", "Output");

	return  mOutputName;
}

bool ConfigManager::Init()
{
	if (FileHelper::IsValidFilePath(mConfigPath, true, true) == false)
		return false;

	if (JsonHelper::File2Json(mConfigPath, mConfigRoot) == false)
		return false;

	return true;
}
