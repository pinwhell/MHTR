#include <OH/ConfigManager.h>
#include <OH/FileHelper.h>
#include <filesystem>

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

std::string ConfigManager::getDumpJsonLibName()
{
	return mDumpJsonLibName;
}

std::string ConfigManager::getGlobalDumpObjectName()
{
	return mGlobalDumpObjName;
}

std::string ConfigManager::getObfuscationBookPath()
{
	return mObfuscationBookPath;
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

	if (InitDumpInfo() == false)
		return false;

	if (InitDynamicDumpInfo() == false)
		return false;

	return true;
}

bool ConfigManager::InitDynamicDumpInfo()
{
	mDumpDynamic = mConfigRoot.get<bool>("dump_dynamic", false);

	if (mDumpDynamic)
	{
		if (JSON_ASSERT_STR_EMPTY(mConfigRoot, "dump_json_lib_name") == false)
		{
			printf("Warning: \"dump_json_lib_name\" not defined in \"%s\", Defaulting to \"jsoncpp\"", mConfigPath.c_str());
			mDumpJsonLibName = "jsoncpp";
			return true;
		}

		mDumpJsonLibName = mConfigRoot.get<std::string>("dump_json_lib_name", "jsoncpp");

		mObfuscationBookMutationEnabled = mConfigRoot.get<bool>("obf_book_mut_enabled", false);

		mObfuscationBookPath = mConfigRoot.get<std::string>("obf_book_path", mMainCategory + "_obf_book.json");
	}

	return true;
}

bool ConfigManager::InitDumpInfo()
{
	mDumpTargetPath = mConfigRoot.get<std::string>("dump_targets_path", "");

	if (FileHelper::IsValidFilePath(mDumpTargetPath, true, true) == false)
		return false;

	mOutputName = mConfigRoot.get<std::string>("output_name", "Output");
	mMainCategory = mConfigRoot.get<std::string>("main_category", "Main");
	mHppOutputPath = mConfigRoot.get<std::string>("hpp_output_path", mOutputName + ".hpp");
	mDeclareGlobalDumpObj = mConfigRoot.get<bool>("declare_dump_global_obj", false);
	mGlobalDumpObjName = mConfigRoot.get<std::string>("global_dump_obj_name", "g" + mMainCategory + "Offs");

	return true;
}

bool ConfigManager::getObfuscationBookMutationEnabled()
{
	return mObfuscationBookMutationEnabled;
}

bool ConfigManager::getDumpDynamic()
{
	return mDumpDynamic;
}

bool ConfigManager::getDeclareGlobalDumpObj()
{
	return mDeclareGlobalDumpObj;
}
