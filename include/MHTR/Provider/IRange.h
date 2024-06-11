#pragma once

#include <memory>
#include <MHTR/Provider/IProvider.h>
#include <MHTR/Range.h>

class IRangeProvider : public IProvider {
public:
    virtual Range GetRange() = 0;
};