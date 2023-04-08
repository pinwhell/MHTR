#include "HardcodedOffsetInfo.h"

bool HardcodedOffsetInfo::Init()
{
    if (IOffset::Init() == false)
        return false;

    return true;
}

void HardcodedOffsetInfo::ComputeOffset()
{
    if (JSON_ASSERT(mOffsetInfo.getMetadata(), "value") == false)
        return;

    uintptr_t value = mOffsetInfo.getMetadata().get<uintptr_t>("value", 0);

    mOffsetInfo.setFinalOffset(value);

    return;
}

void HardcodedOffsetInfo::ComputeJsonResult()
{
    if (getDumpDynamic())
        getResultJson()->set<uint64_t>(mOffsetInfo.getUIDHashStr(), mOffsetInfo.getFinalObfOffset());
}
