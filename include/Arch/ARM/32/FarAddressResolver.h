#pragma once

#include <cstdint>
#include <CStone/ICapstone.h>
#include <IFarAddressResolver.h>

class ARM32FarAddressResolver : public IFarAddressResolver {
public:
    ARM32FarAddressResolver(ICapstone* capstone);

    uint64_t TryResolve(uint64_t at, bool bDerref = false) override;

    ICapstone* mCapstone;
};