#pragma once
#include "IOffsetScanAlgo.h"
class NestedPatternScanAlgo : public IOffsetScanAlgo
{
private:
	std::vector<uintptr_t> mFunctionsCallResult;
	std::string mCallPattern;
	int64_t mCallDisp;
	std::string mPattern;
	uintptr_t mFuncEntry;
	size_t mFuncSize;
public:

	bool Init() override;
	void IgniteScan() override;
};

