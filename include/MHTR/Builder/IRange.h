#pragma once

#include <MHTR/Range.h>

namespace MHTR {
    class IRangeBuilder {
    public:
        virtual ~IRangeBuilder() {};
        virtual Range CreateRange() = 0;
    };
}
