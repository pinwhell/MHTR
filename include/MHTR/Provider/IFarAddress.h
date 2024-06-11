#pragma once

#include <CStone/IProvider.h>
#include <MHTR/Resolver/IFarAddress.h>

class IFarAddressResolverProvider {
public:
    virtual IFarAddressResolver* GetFarAddressResolver(ICapstoneProvider* cstoneProvider) = 0;
    virtual ~IFarAddressResolverProvider() {}
};