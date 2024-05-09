#pragma once

#include <cstdint>

class IRelativeDispProvider {
public:
    virtual uint64_t OffsetFromBase(uint64_t what) const = 0;
};