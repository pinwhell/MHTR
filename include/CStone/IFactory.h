#pragma once

#include <memory>
#include <CStone/ICapstone.h>

class ICapstoneFactory {
public:
    virtual std::unique_ptr<ICapstone> CreateCapstoneInstance(bool bDetailedInst = true) = 0;
};