#pragma once

#include <Range.h>

class IRangeBuilder {
public:
    virtual ~IRangeBuilder() {};
    virtual Range CreateRange() = 0;
};
