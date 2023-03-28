#include "SingleDumpTarget.h"

bool SingleDumpTarget::Init()
{
	if (mTargetJsonPath.empty())
		return false;


	return false;
}

void SingleDumpTarget::AddOffset(std::unique_ptr<IOffset>& offset)
{
	auto* pCurr = offset.get();

	if (mOffsets.find(pCurr) != mOffsets.end())
		return;

	mOffsets[pCurr] = std::move(offset);
}

void SingleDumpTarget::RemoveOffset(IOffset* offset)
{
	if (mOffsets.find(offset) != mOffsets.end())
		return;

	mOffsets.erase(offset);
}

void SingleDumpTarget::ComputeAll()
{
	for (auto& kv : mOffsets)
		kv.second->ComputeOffset();
}