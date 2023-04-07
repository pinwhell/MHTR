#include "Arm32CapstoneHelperFactory.h"
#include "ICapstoneHelper.h"
#include "Arm32CapstoneHelper.h"

Arm32CapstoneHelperFactory::Arm32CapstoneHelperFactory(bool bIsThumb)
    : mIsThumb(bIsThumb)
{
}

ICapstoneHelper* Arm32CapstoneHelperFactory::MakeHelper()
{
    if (mIsThumb == false)
        return new Arm32CapstoneHelper();
}
