#include <MHTR/Range.h>

Range::Range(const void* buff, size_t len)
    : mStart(buff)
    , mEnd((unsigned char*)buff + len)
{}

const void* Range::GetStart() const
{
    return mStart;
}

const void* Range::GetEnd() const
{
    return mEnd;
}
