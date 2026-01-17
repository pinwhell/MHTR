#pragma once

#include <cstdint>

#include <CStone/IProvider.h>
#include <MHTR/Resolver/IFarAddress.h>

namespace MHTR {

    class AArch64FarAddressResolver : public IFarAddressResolver {
    public:
        AArch64FarAddressResolver(ICapstoneProvider* cstoneProvider);

        uint64_t TryResolve(uint64_t at, bool bDerref = false) override;

        ICapstoneProvider* mCStoneProvider;
    };

}
