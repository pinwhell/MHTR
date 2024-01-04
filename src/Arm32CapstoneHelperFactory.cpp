#include <OH/Arm32CapstoneHelperFactory.h>
#include <OH/Arm32CapstoneHelper.h>

ICapstoneHelper* Arm32CapstoneHelperFactory::MakeHelper()
{
    return new Arm32CapstoneHelper();
}
