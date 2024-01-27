#include <OH/ConfigManager.h>
#include <OH/FileHelper.h>
#include <filesystem>

namespace fs = std::filesystem;

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

		mObfustationBookDoMutate = mConfigRoot.get<bool>("obf_book_do_mutate", false);

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
	mDumpEncrypt = mConfigRoot.get<bool>("dump_encrypt", false);
	mDumpRuntime = mConfigRoot.get<bool>("dump_runtime", false);
	mIdentifierSalt = mConfigRoot.get<bool>("identifier_salt", false);
	mIdentifierHash = mConfigRoot.get<bool>("identifier_hash", false);

	return true;
}