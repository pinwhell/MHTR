#include <OH/ObfuscationManager.h>
#include <OH/JsonHelper.h>
#include <OH/FileHelper.h>
#include <OH/RandManager.h>

bool ObfuscationManager::Init()
{
	if (mConfigMgr == nullptr)
		return false;

	if (Import() == false)
		return false;
	
	return true;
}

bool ObfuscationManager::Import()
{
	if (mConfigMgr == nullptr)
		return false;

	if (FileHelper::FileExist(mConfigMgr->mObfuscationBookPath))
	{
		if (FileHelper::IsValidFilePath(mConfigMgr->mObfuscationBookPath, true, true) == false)
			return false;

		if (FileHelper::FileIsEmpty(mConfigMgr->mObfuscationBookPath) == false && JsonHelper::File2Json(mConfigMgr->mObfuscationBookPath, mObfuscationInfoBookRoot) == false)
			return false;
	}

	return true;
}

bool ObfuscationManager::Export()
{
	if (mConfigMgr == nullptr)
		return false;

	return JsonHelper::Json2File(mObfuscationInfoBookRoot, mConfigMgr->mObfuscationBookPath);
}

bool ObfuscationManager::getObfInfoPage(const std::string& uId, JsonValueWrapper& outPage)
{
	if (JSON_ASSERT(mObfuscationInfoBookRoot, uId) == false)
	{
		outPage = JsonValueWrapper();

		outPage["salt_key"] = 0;
		outPage["obf_key"] = 0;

		return false;
	}

	outPage = mObfuscationInfoBookRoot[uId];

	return true;
}

bool ObfuscationManager::getObfInfoPageUpdateMutation(const std::string& uId, JsonValueWrapper& outPage)
{
	if (mConfigMgr->mObfustationBookDoMutate)
		MutatePage(uId);

	return getObfInfoPage(uId, outPage);
}

void ObfuscationManager::UpdateObfInfoPage(const std::string& uId, JsonValueWrapper& page)
{
	mObfuscationInfoBookRoot[uId] = page;
}

void ObfuscationManager::MutatePage(JsonValueWrapper& page)
{
	page["salt_key"] = RandManager::genLargeUint32();
	page["obf_key"] = RandManager::genLargeUint32();
}

bool ObfuscationManager::MutatePage(const std::string& uId)
{
	if (mMutatedUIDs.find(uId) != mMutatedUIDs.end())
		return false;

	JsonValueWrapper page;

	if (JSON_ASSERT(mObfuscationInfoBookRoot, uId) == true)
		page = mObfuscationInfoBookRoot[uId];

	MutatePage(page);
	mObfuscationInfoBookRoot[uId] = page;
	mMutatedUIDs.insert(uId); // so we avoid mutating it again

	return true;
}

uint32_t ObfuscationManager::getSaltKey(const std::string& uId)
{
	JsonValueWrapper page;

	getObfInfoPageUpdateMutation(uId, page);

	return page.get<uint32_t>("salt_key", 0);
}

uint32_t ObfuscationManager::getObfKey(const std::string& uId)
{
	JsonValueWrapper page;

	getObfInfoPageUpdateMutation(uId, page);

	return page.get<uint32_t>("obf_key", 0);
}

void ObfuscationManager::setConfigManager(ConfigManager* cfgMgr)
{
	mConfigMgr = cfgMgr;
}