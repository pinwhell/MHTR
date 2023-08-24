#include "Arm32ThumbCapstoneHelperFactory.h"
#include "Arm32ThumbCapstoneHelper.h"

ICapstoneHelper* Arm32ThumbCapstoneHelperFactory::MakeHelper()
{
    return new Arm32ThumbCapstoneHelper();
}
