#pragma once

#include <cstddef>
#include <cstdint>
#include <MHTR/IRange.h>

namespace MHTR {
    struct Range : public IRange {
        Range(const void* buff, size_t len);

        const void* GetStart() const;
        const void* GetEnd() const;

        template<typename T = const void*>
        inline T GetStart() const
        {
            return (T)GetStart();
        }

        template<typename T = const void*>
        inline T GetEnd() const {
            return (T)GetEnd();
        }

        const void* mStart;
        const void* mEnd;
    private:
    };
}