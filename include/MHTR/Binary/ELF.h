#pragma once

#include <memory>
#include <vector>
#include <ELFPP/ELFPP.hpp>
#include <MHTR/Range.h>
#include <MHTR/Binary/IBinary.h>
#include <MHTR/OffsetCalculator.h>
#include <MHTR/Provider/IBinaryArchMode.h>
#include <CStone/ICapstone.h>

namespace MHTR {
    class ELFBinary : public IBinary {
        using EELFMachine = ELFPP::EMachine;
    public:
        ELFBinary(const void* entry, IBinaryArchModeProvider* archModeProvider = 0);

        std::unique_ptr<ICapstone> CreateInstance(bool bDetailedInst = true) override;
        IFarAddressResolver* GetFarAddressResolver(ICapstoneProvider* cstoneProvider) override;
        Range GetRange() override;
        IOffsetCalculator* GetOffsetCalculator() override;
        ECapstoneArchMode TryDeduceArchMode();

        const void* mEntry;
        std::unique_ptr<ELFPP::IELF> mELF;
        std::unordered_map<std::string, std::unique_ptr<IFarAddressResolver>> mFarAddressResolvers;
        OffsetCalculator mDefaultCalculator;
        IBinaryArchModeProvider* mArchModeProvider;

    private:
        void Map();
        std::vector<uint8_t> mMappedBuffer;
        size_t mMappedSize = 0;
    };
}