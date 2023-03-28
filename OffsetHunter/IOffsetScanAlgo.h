#pragma once

#include "IScanListener.h"
#include <vector>

class FutureOffset;

class IOffsetScanAlgo : public IScanListener
{
private:
	FutureOffset* mParent;
	std::vector<uint64_t> mResults;

public:
	void IgniteScan();
	virtual void OnScanFinished();
	const std::vector<uint64_t>& getResults();
};

