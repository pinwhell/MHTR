#pragma once

#include <CStone/IFactory.h>
#include <Provider/IFarAddress.h>
#include <Provider/IRange.h>
#include <Provider/IOffsetCalculator.h>

class IBinary : public IRangeProvider, public ICapstoneFactory, public IFarAddressResolverProvider, public IOffsetCalculatorProvider {
public:
    virtual ~IBinary() {}
};
