#pragma once

#include "ICapstoneHelper.h"
#include "ICapstoneHelperFactory.h"
#include <unordered_set>
#include <memory>

class CapstoneHelperProvider
{
private:
	std::unordered_set<std::unique_ptr<ICapstoneHelper>> mAllHelpers;
public:

	ICapstoneHelper* getInstance(std::unique_ptr<ICapstoneHelperFactory>&& helperFactory);
};