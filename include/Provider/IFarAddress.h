#pragma once

#include <Resolver/IFarAddress.h>
#include <CStone/IProvider.h>

class IFarAddressResolverProvider {
public:
    virtual IFarAddressResolver* GetFarAddressResolver(ICapstoneProvider* cstoneProvider) = 0;
};