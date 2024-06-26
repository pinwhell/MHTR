#include <unordered_set>
#include <fmt/core.h>
#include <MHTR/Exception/Multi.h>
#include <MHTR/Metadata/Target.h>
#include <MHTR/Metadata/Lookups.h>
#include <MHTR/FarAddressLookup.h>

using namespace MHTR;

FarAddressLookup::FarAddressLookup(MetadataTarget& target, IAddressesProvider* insnAddrsProvider, IFarAddressResolver* farAddrResolver, IOffsetCalculator* offsetCalculator, bool bDeref)
    : mTarget(target)
    , mInsnAddressesProvider(insnAddrsProvider)
    , mFarAddressResolver(farAddrResolver)
    , mOffsetCalculator(offsetCalculator)
    , mDeref(bDeref)
{}

MetadataTarget* FarAddressLookup::GetTarget()
{
    return &mTarget;
}

void FarAddressLookup::Lookup()
{
    if (mTarget.mHasResult)
        return;

    std::vector<uint64_t> insnAddresses = mInsnAddressesProvider->GetAllAddresses();
    std::unordered_set<uint64_t> addrRes;

    std::vector<std::string> errs;

    for (const auto insnAddr : insnAddresses)
    {
        try {
            auto farAddr = mFarAddressResolver->TryResolve(insnAddr, mDeref);
            addrRes.insert(mOffsetCalculator->ComputeOffset(farAddr));
        }
        catch (const std::exception& e)
        {
            errs.push_back(e.what());
        }
    }

    if (addrRes.size() < 1)
    {
        if (errs.empty())
            throw MetadataLookupException(fmt::format("'{}' no far-addresses found.", mTarget.GetFullName()));
        else
            throw MetadataLookupException(fmt::format("'{}' {}", mTarget.GetFullName(), MultiException(errs).what()));
    }

    if (addrRes.size() > 1)
        throw MetadataLookupException(fmt::format("'{}' multiple diferent far-addresses found.", mTarget.GetFullName()));

    mTarget.TrySetResult(MetadataResult(*addrRes.begin()));
}