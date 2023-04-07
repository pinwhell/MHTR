#include "CapstoneHelperProvider.h"

ICapstoneHelper* CapstoneHelperProvider::getInstance(std::unique_ptr<ICapstoneHelperFactory>&& helperFactory)
{
	std::unique_ptr<ICapstoneHelperFactory> factory = std::move(helperFactory);
	std::unique_ptr<ICapstoneHelper> instance(factory->MakeHelper());
	ICapstoneHelper* pinstance = instance.get();

	mAllHelpers.insert(std::move(instance));

	return pinstance;
}

bool CapstoneHelperProvider::CreateHelperFromBinary(const unsigned char* pBin, ICapstoneHelper** pOutHelper)
{



	return false;
}
