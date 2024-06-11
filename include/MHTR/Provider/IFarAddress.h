#pragma once

#include <CStone/IProvider.h>
#include <MHTR/Resolver/IFarAddress.h>

namespace MHTR {
    class IFarAddressResolverProvider {
    public:
        virtual IFarAddressResolver* GetFarAddressResolver(ICapstoneProvider* cstoneProvider) = 0;
        virtual ~IFarAddressResolverProvider() {}
    };
}