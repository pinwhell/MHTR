#pragma once

#include "ICapstoneHelperFactory.h"

class Arm32ThumbCapstoneHelperFactory : public ICapstoneHelperFactory
{
public:
	ICapstoneHelper* MakeHelper() override;
};

