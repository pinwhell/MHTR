#pragma once

#include <Provider/IProvider.h>
#include <cstdint>

class IRelativeDispProvider : public IProvider {
public:
    virtual uint64_t OffsetFromBase(uint64_t what) const = 0;
};