#include "ICapstoneHelper.h"

ICapstoneHelper::ICapstoneHelper()
{
    setMode(CS_MODE_LITTLE_ENDIAN);
}

bool ICapstoneHelper::Init()
{
    if (cs_open(mArch, mMode, &mHandle) != CS_ERR_OK)
        return false;

    if (cs_option(mHandle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
        return false;

    return true;
}

void ICapstoneHelper::setArch(cs_arch arch)
{
    mArch = arch;
}

void ICapstoneHelper::setMode(cs_mode mode)
{
    mMode = mode;
}
