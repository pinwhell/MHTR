#include <MHTR/OffsetCalculator.h>

using namespace MHTR;

OffsetCalculator::OffsetCalculator(IRangeProvider* rangeProvider)
    : mRangeProvider(rangeProvider)
{}

uint64_t OffsetCalculator::ComputeOffset(const void* at)
{
    auto range = mRangeProvider->GetRange();
    return (uint64_t)((char*)at - range.GetStart<char*>());
}
