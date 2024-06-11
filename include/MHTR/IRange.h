#pragma once

namespace MHTR {
    struct IRange {
        virtual ~IRange() {}

        virtual const void* GetStart()  const = 0;
        virtual const void* GetEnd()    const = 0;

        template<typename T = const void*>
        inline T GetStart() const
        {
            return (T)GetStart();
        }

        template<typename T = const void*>
        inline T GetEnd() const {
            return (T)GetEnd();
        }
    };
}