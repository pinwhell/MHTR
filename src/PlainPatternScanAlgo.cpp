#include <OH/PlainPatternScanAlgo.h>
#include <OH/FutureOffset.h>
#include <ThunderByteScan.hpp>

bool PlainPatternScanAlgo::Init()
{
    if (IOffsetScanAlgo::Init() == false)
        return false;

    if (JSON_ASSERT_STR_EMPTY(mAlgoMetadata, "pattern") == false)
    {
        std::string name = mParent->getName();

        printf("Field \"pattern\" not found or empty at to find \"%s\"\n", name.c_str());

        return false;
    }

    mPattern = mAlgoMetadata.get<std::string>("pattern", "");

    return true;
}

void PlainPatternScanAlgo::IgniteScan()
{
    IOffsetScanAlgo::IgniteScan();

    ThunderByteScan::LocalFindPattern(mPattern, (uintptr_t)mBuffer, (uintptr_t)mBuffer + mBuffSize, mResults);

    ContainerDisplacer::Displace<std::vector<uintptr_t>, int64_t>(mResults.begin(), mResults.end(), -((int64_t)mBuffer));

    IOffsetScanAlgo::OnScanFinished();
}
