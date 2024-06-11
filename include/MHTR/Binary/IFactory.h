#pragma once

#include <memory>
#include <MHTR/IRange.h>
#include <MHTR/Binary/IBinary.h>

namespace MHTR {
    class IBinaryFactory {
    public:
        virtual std::unique_ptr<IBinary> CreateBinary() = 0;
        virtual ~IBinaryFactory() {}
    };
}