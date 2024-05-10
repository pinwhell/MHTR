#include <Provider/Range.h>

RangeProvider::RangeProvider(const BufferView& buffView)
    : mBuffView(buffView)
{}

BufferView RangeProvider::GetRange()
{
    return mBuffView;
}