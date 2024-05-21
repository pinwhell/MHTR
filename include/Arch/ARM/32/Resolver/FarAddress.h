#pragma once

#include <cstdint>

#include <CStone/IProvider.h>
#include <Resolver/IFarAddress.h>

class ARM32FarAddressResolver : public IFarAddressResolver {
public:
    ARM32FarAddressResolver(ICapstoneProvider* cstoneProvider);

    uint64_t TryResolve(uint64_t at, bool bDerref = false) override;

    ICapstoneProvider* mCStoneProvider;
};