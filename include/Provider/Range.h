#pragma once

#include <Provider/IRange.h>

class RangeProvider : public IRangeProvider {
public:
    RangeProvider(const BufferView& buffView);

    BufferView GetRange() override;

    BufferView mBuffView;
};