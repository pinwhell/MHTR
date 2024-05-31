#pragma once

#include <memory>
#include <IRange.h>
#include <Binary/IBinary.h>

class IBinaryFactory {
public:
    virtual std::unique_ptr<IBinary> CreateBinary() = 0;
    virtual ~IBinaryFactory() {}
};