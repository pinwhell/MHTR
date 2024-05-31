#pragma once

#include <memory>
#include <ELFPP.hpp>
#include <Range.h>
#include <CStone/ICapstone.h>
#include <Binary/IBinary.h>
#include <OffsetCalculator.h>

class ELFBinary : public IBinary {
    using EELFMachine = ELFPP::EMachine;
public:
    ELFBinary(const void* entry);

    std::unique_ptr<ICapstone> CreateInstance(bool bDetailedInst = true) override;
    IFarAddressResolver* GetFarAddressResolver(ICapstoneProvider* cstoneProvider) override;
    Range GetRange() override;
    IOffsetCalculator* GetOffsetCalculator() override;

    const void* mEntry;
    std::unique_ptr<ELFPP::IELF> mELF;
    std::unordered_map<std::string, std::unique_ptr<IFarAddressResolver>> mFarAddressResolvers;
    OffsetCalculator mDefaultCalculator;
};