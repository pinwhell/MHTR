#include "TargetManager.h"
#include "FileHelper.h"
#include "DumpTargetGroup.h"

bool TargetManager::Init()
{
	if (FileHelper::IsValidFilePath(mDumpTargetsPath, true, true) == false)
		return false;

	if (JsonHelper::File2Json(mDumpTargetsPath, mDumpTargetsRoot) == false)
	{
		printf("Unable to parse DUmp Targets\n");
		return false;
	}

	if (ReadAllTargets() == false)
		return false;

	if (InitAllTargets() == false)
		return false;


	return true;
}

bool TargetManager::InitAllTargets()
{
	for (const auto& kv : mAllTargets)
	{
		if (kv.second->Init() == false)
			return false;
	}

	return true;
}

void TargetManager::ComputeAll()
{
	for (const auto& kv : mAllTargets)
		kv.second->ComputeAll();
}

void TargetManager::RemoveTarget(IDumpTarget* target)
{
	if (mAllTargets.find(target) == mAllTargets.end())
		return;

	mAllTargets.erase(target);
}

void TargetManager::AddTarget(std::unique_ptr<IDumpTarget>& target)
{
	IDumpTarget* pDumpTarget = target.get();

	if (mAllTargets.find(pDumpTarget) != mAllTargets.end())
		return;

	mAllTargets[pDumpTarget] = std::move(target);
}

void TargetManager::setDumpTargetPath(const std::string& path)
{
	mDumpTargetsPath = path;
}

bool TargetManager::ReadAllTargets()
{
	if (mDumpTargetsRoot.isArray() == false)
	{
		printf("Unexpected Format of the \"%s\"\n", mDumpTargetsPath.c_str());
		return false;
	}

	for (size_t i = 0; i < mDumpTargetsRoot.size(); i++) // All Targets
	{
		JsonValueWrapper curr(mDumpTargetsRoot[i]);

		HandleTargetGroupJson(curr);
	}

	return true;
}

bool TargetManager::HandleTargetGroupJson(const JsonValueWrapper& targetGroupRoot)
{
	if (JSON_IS_MEMBER(targetGroupRoot, "macro") == false || JSON_IS_MEMBER(targetGroupRoot, "targets") == false)
		return false;

	std::unique_ptr<IDumpTarget> targetGroup = std::make_unique<DumpTargetGroup>();

	((DumpTargetGroup*)targetGroup.get())->setDumpTargetDescJson(targetGroupRoot);

	AddTarget(targetGroup);

	return true;
}
