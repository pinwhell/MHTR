#include <OH/HardcodedOffsetInfo.h>

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

void HardcodedResultInfo::Compute()
{
    IFutureResult::Compute();

    uintptr_t value = JsonUint64Get(mMetadata, "value");
    size_t disp = JsonUint64Get(mMetadata, "disp");

    mFutureResultInfo.setFinalOffset(value + disp);

    onSucessfullyComputed();
}

void HardcodedResultInfo::ComputeJsonResult()
{
    if (getDumpDynamic())
        getResultJson()->set<uint64_t>(mFutureResultInfo.getUIDHashStr(), mFutureResultInfo.getFinalObfOffset());
}
