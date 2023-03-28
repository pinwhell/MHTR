#pragma once

#include "ICapstoneHelper.h"

class ICapstoneHelperFactory
{
public:
	virtual ICapstoneHelper* MakeHelper() = 0;
};

