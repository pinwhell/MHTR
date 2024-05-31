#pragma once

#include <memory>
#include <Provider/IProvider.h>
#include <Range.h>

class IRangeProvider : public IProvider {
public:
    virtual Range GetRange() = 0;
};