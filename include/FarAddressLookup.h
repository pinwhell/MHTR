#pragma once

#include <Metadata.h>
#include <IAddressesProvider.h>
#include <IFarAddressResolver.h>
#include <IRelativeDispProvider.h>

class FarAddressLookup : public ILookable {
public:
    FarAddressLookup(MetadataTarget& target, IAddressesProvider* insnAddrsProvider, IFarAddressResolver* farAddrResolver, IRelativeDispProvider* dispCalculator, bool bDeref = false);

    void Lookup() override;

    MetadataTarget& mTarget;
    IAddressesProvider* mInsnAddressesProvider;
    IFarAddressResolver* mFarAddressResolver;
    IRelativeDispProvider* mDispCalculator;
    bool mDeref;
};