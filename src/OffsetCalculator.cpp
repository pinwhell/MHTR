#include <OffsetCalculator.h>

OffsetCalculator::OffsetCalculator(IRangeProvider* rangeProvider)
    : mRangeProvider(rangeProvider)
{}

uint64_t OffsetCalculator::ComputeOffset(const void* at)
{
    auto range = mRangeProvider->GetRange();
    return (uint64_t)(range.GetStart<char*>() - (char*)at);
}
