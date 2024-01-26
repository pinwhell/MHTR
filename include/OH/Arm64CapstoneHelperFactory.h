#pragma once
#include "ICapstoneHelperFactory.h"

class Arm64CapstoneHelperFactory : public ICapstoneHelperFactory
{
private:
public:
	ICapstoneHelper* MakeHelper() override;
};

