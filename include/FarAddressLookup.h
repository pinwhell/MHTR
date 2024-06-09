#pragma once

#include <Resolver/IFarAddress.h>
#include <Provider/IAddresses.h>
#include <IOffsetCalculator.h>
#include <ILookableMetadata.h>

class FarAddressLookup : public ILookableMetadata {
public:
    FarAddressLookup(MetadataTarget& target, IAddressesProvider* insnAddrsProvider, IFarAddressResolver* farAddrResolver, IOffsetCalculator* offsetCalculator, bool bDeref = false);

    MetadataTarget* GetTarget() override;
    void Lookup() override;

    MetadataTarget& mTarget;
    IAddressesProvider* mInsnAddressesProvider;
    IFarAddressResolver* mFarAddressResolver;
    IOffsetCalculator* mOffsetCalculator;
    bool mDeref;
};