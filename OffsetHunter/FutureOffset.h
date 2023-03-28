#pragma once
#include "IOffset.h"
#include "IOffsetScanAlgo.h"
#include "IScanListener.h"
#include <memory>



class FutureOffset : public IOffset, public IScanListener
{
public:
	enum class Status
	{
		IDDLE,
		RUNNING,
		FINISH
	};

private:
	Status mStatus;
	std::unique_ptr<IOffsetScanAlgo> mScanAlgo;

public:

	FutureOffset();

	void OnScanFinished() override;

	void OnFound();
	void OnNotFound();
	void OnMultipleFound();

	void IgniteScan();
	void ComputeOffset() override;
};

