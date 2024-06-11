#pragma once

#include <MHTR/Binary/IBinary.h>

class UnknownBinary : public IBinary {
public:
    std::unique_ptr<ICapstone> CreateInstance(bool bDetailedInst) override;
    IFarAddressResolver* GetFarAddressResolver(ICapstoneProvider* cstoneProvider) override;
    Range GetRange() override;
    IOffsetCalculator* GetOffsetCalculator() override;
};
