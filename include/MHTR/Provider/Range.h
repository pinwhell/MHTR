#pragma once

#include <MHTR/Provider/IRange.h>

namespace MHTR {
    class RangeProvider : public IRangeProvider {
    public:
        RangeProvider(const Range& buffView);

        Range GetRange() override;

        Range mBuffView;
    };
}