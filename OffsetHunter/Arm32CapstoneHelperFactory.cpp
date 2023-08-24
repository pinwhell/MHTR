#include "Arm32CapstoneHelperFactory.h"
#include "Arm32CapstoneHelper.h"

ICapstoneHelper* Arm32CapstoneHelperFactory::MakeHelper()
{
    return new Arm32CapstoneHelper();
}
