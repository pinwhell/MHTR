#pragma once
#include "ICapstoneHelperFactory.h"

class Arm32CapstoneHelperFactory : public ICapstoneHelperFactory
{
private:
	bool mIsThumb;
public:
	Arm32CapstoneHelperFactory(bool bIsThumb = false);

	ICapstoneHelper* MakeHelper() override;
};

