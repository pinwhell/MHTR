#pragma once

#include <IOffsetCalculator.h>
#include <Provider/IRange.h>

class OffsetCalculator : public IOffsetCalculator {
public:
    OffsetCalculator(IRangeProvider* rangeProvider);

    uint64_t ComputeOffset(const void* at) override;

    IRangeProvider* mRangeProvider;
};
