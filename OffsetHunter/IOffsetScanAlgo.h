#pragma once

#include "IScanListener.h"
#include <vector>
#include "JsonValueWrapper.h"

class FutureOffset;

class IOffsetScanAlgo : public IScanListener
{
private:
	FutureOffset* mParent;
	std::vector<uint64_t> mResults;
	JsonValueWrapper mAlgoMetadata;

public:
	virtual bool Init() = 0;
	virtual void IgniteScan();
	virtual void OnScanFinished();
	const std::vector<uint64_t>& getResults();
	void setAlgoMetadata(const JsonValueWrapper& metadata);
};

