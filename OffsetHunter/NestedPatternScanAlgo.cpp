#include "NestedPatternScanAlgo.h"
#include "FutureOffset.h"
#include <ThunderByteScan.hpp>

NestedPatternScanAlgo::NestedPatternScanAlgo()
{
    mNeedCapstone = true;
}

bool NestedPatternScanAlgo::Init()
{
    if (IOffsetScanAlgo::Init() == false)
        return false;

    std::string name = mParent->getName();

    if (JSON_ASSERT_STR_EMPTY(mAlgoMetadata, "pattern") == false)
    {
        printf("Field \"pattern\" not found or empty at to find \"%s\"\n", name.c_str());
        return false;
    }

    if (JSON_ASSERT_STR_EMPTY(mAlgoMetadata, "call") == false)
    {
        printf("Field \"call\" not found or empty at to find \"%s\"\n", name.c_str());
        return false;
    }

    mPattern = mAlgoMetadata.get<std::string>("pattern", "");
    mCallPattern = mAlgoMetadata.get<std::string>("call", "");
    mCallDisp = mAlgoMetadata.get<int64_t>("cdisp", 0);
    mMainDisp = mAlgoMetadata.get<int64_t>("pdisp", 0);

    return true;
}

void NestedPatternScanAlgo::IgniteScan()
{
    IOffsetScanAlgo::IgniteScan();

    ThunderByteScan::LocalFindPattern(mCallPattern, (uintptr_t)mBuffer, (uintptr_t)mBuffer + mBuffSize, mFunctionsCallResult);

    ContainerDisplacer::Displace<std::vector<uintptr_t>, int64_t>(mFunctionsCallResult.begin(), mFunctionsCallResult.end(), mCallDisp);

    // Now you must filter out the ones that are not calls
    // You must also filter out that there is at least one call

    ThunderByteScan::LocalFindPattern(mPattern, mFuncEntry, mFuncEntry + mFuncSize, mResults);

    ContainerDisplacer::Displace<std::vector<uintptr_t>, int64_t>(mResults.begin(), mResults.end(), -((int64_t)mBuffer));

    IOffsetScanAlgo::OnScanFinished();
}
