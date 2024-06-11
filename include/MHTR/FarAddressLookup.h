#pragma once

#include <MHTR/Resolver/IFarAddress.h>
#include <MHTR/Provider/IAddresses.h>
#include <MHTR/IOffsetCalculator.h>
#include <MHTR/ILookableMetadata.h>

namespace MHTR {

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

}