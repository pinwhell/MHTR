#include "Arm32CapstoneHelperFactory.h"
#include "ICapstoneHelper.h"

Arm32CapstoneHelperFactory::Arm32CapstoneHelperFactory(bool bIsThumb)
    : mIsThumb(bIsThumb)
{
}

ICapstoneHelper* Arm32CapstoneHelperFactory::MakeHelper()
{
    ICapstoneHelper* mHelper = new ICapstoneHelper();

    mHelper->setArch(CS_ARCH_ARM);
    mHelper->setMode(mIsThumb ? CS_MODE_THUMB : CS_MODE_ARM);

    return mHelper;
}
