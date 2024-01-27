#pragma once

#include <string>
#include <json/json.h>
#include <OH/JsonValueWrapper.h>

class ConfigManager
{
public:
	std::string mConfigPath;
	JsonValueWrapper mConfigRoot;

	bool mDumpDynamic;
	bool mDumpRuntime;
	bool mDumpEncrypt;
	bool mIdentifierSalt;
	bool mIdentifierHash;

	std::string mMainCategory;
	std::string mOutputName;
	std::string mDumpTargetPath;
	std::string mHppOutputPath;
	std::string mDumpJsonLibName;
	std::string mGlobalDumpObjName;
	std::string mObfuscationBookPath;

	bool mDeclareGlobalDumpObj;
	bool mObfustationBookDoMutate;

	bool Init();
	bool InitDynamicDumpInfo();
	bool InitDumpInfo();
};