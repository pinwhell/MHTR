#include <Provider/Range.h>

RangeProvider::RangeProvider(const Range& buffView)
    : mBuffView(buffView)
{}

Range RangeProvider::GetRange()
{
    return mBuffView;
}