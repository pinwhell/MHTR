#pragma once

#include <CStone/ICapstone.h>
#include <CStone/IFactory.h>

class ICapstoneInstanceProvider {
public:
    virtual ICapstone* GetInstance(bool bDetailedInstuction = true, ICapstoneFactory* _factory = nullptr) = 0;
};