#include "HardcodedOffsetInfo.h"

bool HardcodedOffsetInfo::Init()
{
    if (IOffset::Init() == false)
        return false;

    return true;
}

void HardcodedOffsetInfo::ComputeOffset()
{
    uintptr_t value = mOffsetInfo.getMetadata().get<uintptr_t>("value", 0);
    size_t disp = mOffsetInfo.getMetadata().get<uintptr_t>("disp", 0);

    mOffsetInfo.setFinalOffset(value + disp);

    return;
}

void HardcodedOffsetInfo::ComputeJsonResult()
{
    if (getDumpDynamic())
        getResultJson()->set<uint64_t>(mOffsetInfo.getUIDHashStr(), mOffsetInfo.getFinalObfOffset());
}
