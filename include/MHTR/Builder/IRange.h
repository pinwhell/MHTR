#pragma once

#include <MHTR/Range.h>

class IRangeBuilder {
public:
    virtual ~IRangeBuilder() {};
    virtual Range CreateRange() = 0;
};
