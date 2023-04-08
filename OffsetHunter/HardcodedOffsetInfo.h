#pragma once
#include "IOffset.h"

class HardcodedOffsetInfo : public IOffset
{
public:
	bool Init() override;
	void ComputeOffset() override;
	void ComputeJsonResult() override;
};

