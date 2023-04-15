#include "HardcodedOffsetInfo.h"

HardcodedResultInfo::HardcodedResultInfo()
{
    mpFutureResultInfo = &mFutureResultInfo;
}

bool HardcodedResultInfo::Init()
{
    if (IFutureResult::Init() == false)
        return false;

    return true;
}

void HardcodedResultInfo::ComputeOffset()
{
    uintptr_t value = mMetadata.get<uintptr_t>("value", 0);
    size_t disp = mMetadata.get<uintptr_t>("disp", 0);

    mFutureResultInfo.setFinalOffset(value + disp);

    return;
}

void HardcodedResultInfo::ComputeJsonResult()
{
    if (getDumpDynamic())
        getResultJson()->set<uint64_t>(mFutureResultInfo.getUIDHashStr(), mFutureResultInfo.getFinalObfOffset());
}
