#include <OH/ObfuscationManager.h>
#include <OH/JsonHelper.h>
#include <OH/FileHelper.h>
#include <OH/RandManager.h>

bool ObfuscationManager::Init()
{
	if (Import() == false)
		return false;
	
	return true;
}

bool ObfuscationManager::Import()
{
	if (FileHelper::FileExist(mObfuscationInfoBookPath))
	{
		if (FileHelper::IsValidFilePath(mObfuscationInfoBookPath, true, true) == false)
			return false;

		if (JsonHelper::File2Json(mObfuscationInfoBookPath, mObfuscationInfoBookRoot) == false)
			return false;
	}

	return true;
}

bool ObfuscationManager::Export()
{
	return JsonHelper::Json2File(mObfuscationInfoBookRoot, mObfuscationInfoBookPath);
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
	if (mObfInfoMutationEnabled)
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

void ObfuscationManager::setPath(const std::string& path)
{
	mObfuscationInfoBookPath = path;
}

void ObfuscationManager::setObfInfoMutationEnabled(bool b)
{
	mObfInfoMutationEnabled = b;
}
