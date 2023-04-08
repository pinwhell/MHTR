#include "NestedPatternScanAlgo.h"
#include "FutureOffset.h"
#include <ThunderByteScan.hpp>
#include "ICapstoneHelper.h"
#include "GeneralHelpers.h"

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

    mTryInterpret = true; // Need to interpret by default the call instruction 

    return true;
}

void NestedPatternScanAlgo::InterpretAllCalls()
{
    for (uintptr_t& c : this->mFunctionsCallResult)
    {
        uintptr_t callDest = 0;

        if (getCapstoneHelper()->TryGetCallDestination((unsigned char*)c, callDest) == false)
        {
            auto sig = mParent->getSignature();
            printf("Unable to resolve \"%s\" candidate \"0x%08X\" call Interpretation\n", sig.c_str(), (unsigned char*)c - (unsigned char*)mBuffer);
            continue;
        }

        if (isBetween((unsigned char*)c,(unsigned char*)mBuffer, (unsigned char*)mBuffer + mBuffSize) == false)
        {
            auto sig = mParent->getSignature();
            printf("\"%s\" call candidate \"%p\" resolves to out of bounds function base\n", sig.c_str(), c);
            continue;
        }

        mResults.push_back(callDest);
    }

    SyncFilteredResults(); // Refactor me

    mFunctionCallsDsts.clear();

    for (uintptr_t& f : mResults)
        mFunctionCallsDsts.push_back(f);

    mResults.clear();
}

void NestedPatternScanAlgo::IgniteScan()
{
    IOffsetScanAlgo::IgniteScan();

    ThunderByteScan::LocalFindPattern(mCallPattern, (uintptr_t)mBuffer, (uintptr_t)mBuffer + mBuffSize, mFunctionsCallResult);

    if (mFunctionsCallResult.size() == 0)
    {
        std::string sig = mParent->getSignature();
        printf("\"%s\" \"%s\" no calls results\n", sig.c_str(), mCallPattern.c_str());
        return;
    }

    ContainerDisplacer::Displace<std::vector<uintptr_t>, int64_t>(mFunctionsCallResult.begin(), mFunctionsCallResult.end(), mCallDisp);

    InterpretAllCalls();

    // if there is multiple Function entries, 
    // then the call pattern is not precise

    if (mFunctionCallsDsts.size() > 1)
    {
        std::string sig = mParent->getSignature();
        printf("\"%s\" \"%s\" call founds with the pattern, lead to diferent functions\n", sig.c_str(), mCallPattern.c_str());
        return;
    }
    else if (mFunctionCallsDsts.size() < 1)
    {
        std::string sig = mParent->getSignature();
        printf("\"%s\" \"%s\" unable to resolve the calls function base(/s)\n", sig.c_str(), mCallPattern.c_str());
        return;
    }

    mFuncEntry = mFunctionCallsDsts[0];
    mFuncSize = mAlgoMetadata.get<size_t>("fsize", 0);

    if ((mFuncSize > 0) == false)
    {
        // Means the user didnt defined the function size, lets try to find it

        if (getCapstoneHelper()->TryComputeParagraphSize((unsigned char*)mFuncEntry, mFuncSize) == false)
        {
            std::string sig = mParent->getSignature();
            printf("\"%s\" \"%s\" unable to calculate the function size, please provide it manually using the \"fsize\" Field\n", sig.c_str(), mCallPattern.c_str());
            return;
        }
    }

    ThunderByteScan::LocalFindPattern(mPattern, mFuncEntry, mFuncEntry + mFuncSize, mResults);

    ContainerDisplacer::Displace<std::vector<uintptr_t>, int64_t>(mResults.begin(), mResults.end(), -((int64_t)mBuffer));

    IOffsetScanAlgo::OnScanFinished();
}
