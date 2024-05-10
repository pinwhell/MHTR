#pragma once

#include <BufferView.h>

class IRangeProvider {
public:
    virtual BufferView GetRange() = 0;
};