#pragma once

#include <Provider/IRange.h>

class RangeProvider : public IRangeProvider {
public:
    RangeProvider(const Range& buffView);

    Range GetRange() override;

    Range mBuffView;
};