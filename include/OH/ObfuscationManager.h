#pragma once

#include "JsonValueWrapper.h"
#include <unordered_set>
#include "IChild.h"
#include <OH/ConfigManager.h>

class TargetManager;

/*

just like a book, where the pages are each "[identifier]" : {
	"salt_key" : xyz,
	"obf_key" : xyz
}

*/
class ObfuscationManager : public IChild<TargetManager>
{
private:
	JsonValueWrapper mObfuscationInfoBookRoot;
	std::unordered_set<std::string> mMutatedUIDs;

	ConfigManager* mConfigMgr;

	bool getObfInfoPage(const std::string& uId, JsonValueWrapper& outPage);
	bool getObfInfoPageUpdateMutation(const std::string& uId, JsonValueWrapper& outPage);
	void UpdateObfInfoPage(const std::string& uId, JsonValueWrapper& page);
	void MutatePage(JsonValueWrapper& page);
	bool MutatePage(const std::string& uId);

public:

	bool Init();

	bool Import();
	bool Export();

	uint32_t getSaltKey(const std::string& uId);
	uint32_t getObfKey(const std::string& uId);

	void setConfigManager(ConfigManager* cfgMgr);
};

