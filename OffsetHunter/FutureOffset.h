#pragma once
#include "IFutureResult.h"
#include "IOffsetScanAlgo.h"
#include "IScanListener.h"
#include "FutureOffsetResultInfo.h"
#include <memory>

class FutureOffset : public IFutureResultImpl<FutureOffsetResultInfo>, public IScanListener
{
private:
	std::unique_ptr<IOffsetScanAlgo> mScanAlgo;

public:

	FutureOffset();

	bool Init() override;
	void OnScanFinished() override;

	void OnFound();
	void OnNotFound();
	void OnMultipleFound();
	uintptr_t getSingleResult();

	void IgniteScan();
	void ComputeOffset() override;
	void ComputeJsonResult() override;
};

