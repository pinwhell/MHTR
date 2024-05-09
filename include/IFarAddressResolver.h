#pragma once

#include <cstdint>

class IFarAddressResolver {
public:
    virtual uint64_t TryResolve(uint64_t at, bool bDerref = false) = 0;
};