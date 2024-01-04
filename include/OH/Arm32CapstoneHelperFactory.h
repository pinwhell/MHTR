#pragma once
#include "ICapstoneHelperFactory.h"

class Arm32CapstoneHelperFactory : public ICapstoneHelperFactory
{
private:
public:
	ICapstoneHelper* MakeHelper() override;
};

