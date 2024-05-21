#pragma once

#include <Provider/IProvider.h>
#include <BufferView.h>

class IRangeProvider : public IProvider {
public:
    virtual BufferView GetRange() = 0;
};