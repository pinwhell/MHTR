#pragma once

#include <MHTR/IOffsetCalculator.h>
#include <MHTR/Provider/IRange.h>

namespace MHTR {
    class OffsetCalculator : public IOffsetCalculator {
    public:
        OffsetCalculator(IRangeProvider* rangeProvider);

        uint64_t ComputeOffset(const void* at) override;

        IRangeProvider* mRangeProvider;
    };
}