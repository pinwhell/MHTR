#include <OH/Arm32ThumbCapstoneHelperFactory.h>
#include <OH/Arm32ThumbCapstoneHelper.h>

ICapstoneHelper* Arm32ThumbCapstoneHelperFactory::MakeHelper()
{
    return new Arm32ThumbCapstoneHelper();
}
