#pragma once
#include "IFutureResult.h"
#include "FutureOffsetResultInfo.h"

class HardcodedResultInfo : public IFutureResultImpl<FutureOffsetResultInfo>
{
public:
	HardcodedResultInfo();
	bool Init() override;
	void ComputeOffset() override;
	void ComputeJsonResult() override;
};

