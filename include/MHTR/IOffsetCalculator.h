#pragma once

#include <cstdint>

class IOffsetCalculator {
public:
    virtual ~IOffsetCalculator() {}
    virtual uint64_t ComputeOffset(const void* at) = 0;

    template<typename T>
    uint64_t ComputeOffset(T at)
    {
        return ComputeOffset((const void*)at);
    }
};