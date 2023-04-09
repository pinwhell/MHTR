#pragma once

#include "JsonValueWrapper.h"
#include <unordered_set>
#include "IChild.h"

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
	std::string mObfuscationInfoBookPath;
	JsonValueWrapper mObfuscationInfoBookRoot;
	bool mObfInfoMutationEnabled;
	std::unordered_set<std::string> mMutatedUIDs;

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

	void setPath(const std::string& path);

	void setObfInfoMutationEnabled(bool b);
};

