#pragma once

#include <Provider/IRelativeDisp.h>

struct BufferView : public IRelativeDispProvider {
    inline BufferView(const void* buff, size_t len)
        : mStart(buff)
        , mEnd((unsigned char*)buff + len)
    {}

    template<typename T = const void*>
    inline T start() const
    {
        return (T)mStart;
    }

    template<typename T = const void*>
    inline T end() const {
        return (T)mEnd;
    }

    inline uint64_t OffsetFromBase(uint64_t what) const override
    {
        return what - start<uint64_t>();
    }

    const void* mStart;
    const void* mEnd;
};