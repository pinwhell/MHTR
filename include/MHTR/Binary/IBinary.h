#pragma once

#include <CStone/IFactory.h>
#include <MHTR/Provider/IFarAddress.h>
#include <MHTR/Provider/IRange.h>
#include <MHTR/Provider/IOffsetCalculator.h>

class IBinary : public IRangeProvider, public ICapstoneFactory, public IFarAddressResolverProvider, public IOffsetCalculatorProvider {
public:
    virtual ~IBinary() {}
};
