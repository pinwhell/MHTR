#include <OH/Arm64CapstoneHelperFactory.h>
#include <OH/Arm64CapstoneHelper.h>

ICapstoneHelper* Arm64CapstoneHelperFactory::MakeHelper()
{
    return new Arm64CapstoneHelper();
}
