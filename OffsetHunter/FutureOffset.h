#pragma once
#include "IOffset.h"
#include "IOffsetScanAlgo.h"
#include "IScanListener.h"
#include <memory>



class FutureOffset : public IOffset, public IScanListener
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

	void IgniteScan();
	void ComputeOffset() override;
};

