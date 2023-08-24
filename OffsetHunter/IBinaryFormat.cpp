#include "IBinaryFormat.h"

bool IBinaryFormat::MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper, std::string mode)
{
	return false;
}

void IBinaryFormat::setBase(uintptr_t base)
{
	mBase = base;
}

void IBinaryFormat::setBase(void* base)
{
	mVBase = base;
}
