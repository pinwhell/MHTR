#include "HardcodedOffsetInfo.h"

bool HardcodedResultInfo::Init()
{
    if (IFutureResult::Init() == false)
        return false;

    return true;
}

void HardcodedResultInfo::ComputeOffset()
{
    uintptr_t value = mIFutureResultInfo.getMetadata().get<uintptr_t>("value", 0);
    size_t disp = mIFutureResultInfo.getMetadata().get<uintptr_t>("disp", 0);

    mIFutureResultInfo.setFinalOffset(value + disp);

    return;
}

void HardcodedResultInfo::ComputeJsonResult()
{
    if (getDumpDynamic())
        getResultJson()->set<uint64_t>(mIFutureResultInfo.getUIDHashStr(), mIFutureResultInfo.getFinalObfOffset());
}
