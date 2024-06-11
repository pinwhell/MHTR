#pragma once

#include <memory>
#include <MHTR/Provider/IProvider.h>
#include <MHTR/Range.h>

namespace MHTR {
    class IRangeProvider : public IProvider {
    public:
        virtual Range GetRange() = 0;
    };
}