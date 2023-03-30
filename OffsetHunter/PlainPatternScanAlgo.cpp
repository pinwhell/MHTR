#include "PlainPatternScanAlgo.h"
#include "FutureOffset.h"

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

    return true;
}

void PlainPatternScanAlgo::IgniteScan()
{
    IOffsetScanAlgo::IgniteScan();
}
