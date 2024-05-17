#include <fmt/core.h>

#include <FarAddressLookup.h>
#include <MultiException.h>
#include <unordered_set>

FarAddressLookup::FarAddressLookup(MetadataTarget& target, IAddressesProvider* insnAddrsProvider, IFarAddressResolver* farAddrResolver, IRelativeDispProvider* dispCalculator, bool bDeref)
    : mTarget(target)
    , mInsnAddressesProvider(insnAddrsProvider)
    , mFarAddressResolver(farAddrResolver)
    , mDispCalculator(dispCalculator)
    , mDeref(bDeref)
{}

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
            addrRes.insert(mDispCalculator->OffsetFromBase(farAddr));
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