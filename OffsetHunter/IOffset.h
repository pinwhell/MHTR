#pragma once

#include "OffsetInfo.h"

class IOffset
{
private:
	OffsetInfo mOffsetInfo;

public:
	virtual void ComputeOffset() = 0;
};

