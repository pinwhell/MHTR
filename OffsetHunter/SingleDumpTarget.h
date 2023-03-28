#pragma once
#include "IDumpTarget.h"
#include "HardcodedOffsetInfo.h"
#include "IOffset.h"
#include <string>
#include <unordered_map>
#include "JsonValueWrapper.h"

class SingleDumpTarget : public IDumpTarget
{
private:
	std::string mCategoryName;
	std::unordered_map<IOffset*, std::unique_ptr<IOffset>> mOffsets;
	CapstoneHelperProvider* mCapstoneHelperProvider;
	std::unique_ptr<ICapstoneHelper> mCapstoneHelper;
	std::string mTargetJsonPath;
	

public:

	bool Init() override;

	void AddOffset(std::unique_ptr<IOffset>& offset);
	void RemoveOffset(IOffset* offset);

	void ComputeAll();
};

