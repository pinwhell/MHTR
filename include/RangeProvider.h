#pragma once

#include <IRangeProvider.h>

class RangeProvider : public IRangeProvider {
public:
    RangeProvider(const BufferView& buffView);

    BufferView GetRange() override;

    BufferView mBuffView;
};