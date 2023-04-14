#pragma once
#include "IFutureResult.h"

class HardcodedResultInfo : public IFutureResult
{
public:
	bool Init() override;
	void ComputeOffset() override;
	void ComputeJsonResult() override;
};

