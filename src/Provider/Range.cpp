#include <MHTR/Provider/Range.h>

using namespace MHTR;

RangeProvider::RangeProvider(const Range& buffView)
    : mBuffView(buffView)
{}

Range RangeProvider::GetRange()
{
    return mBuffView;
}