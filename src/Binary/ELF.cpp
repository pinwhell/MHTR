#include <fmt/core.h>
#include <MHTR/Binary/ELF.h>
#include <MHTR/Arch/ARM/32/Resolver/FarAddress.h>
#include <CStone/Factory.h>

using namespace MHTR;

ELFBinary::ELFBinary(const void* entry, IBinaryArchModeProvider* archModeProvider)
    : mEntry(entry)
    , mELF(ELFPP::FromBuffer(mEntry))
    , mDefaultCalculator(this)
    , mArchModeProvider(archModeProvider)
{}

std::unique_ptr<ICapstone> ELFBinary::CreateInstance(bool bDetailedInst)
{
    auto archMode = mArchModeProvider ? mArchModeProvider->GetBinaryArchMode() : TryDeduceArchMode();
    archMode = archMode == ECapstoneArchMode::UNDEFINED ? TryDeduceArchMode() : archMode;
    return CapstoneFactory(archMode).CreateInstance(bDetailedInst);
}

IFarAddressResolver* ELFBinary::GetFarAddressResolver(ICapstoneProvider* cstoneProvider)
{
    auto machine = mELF->GetTargetMachine();
    bool bIs64 = mELF->Is64();
    std::string key = fmt::format("{}{}{}", fmt::ptr(cstoneProvider), (int)machine, bIs64);

    if (mFarAddressResolvers.find(key) != mFarAddressResolvers.end())
        return mFarAddressResolvers[key].get();

    if (machine == EELFMachine::ARM && !bIs64)
        return (mFarAddressResolvers[key] = std::make_unique<ARM32FarAddressResolver>(cstoneProvider)).get();

    return nullptr;
}

Range ELFBinary::GetRange()
{
    return Range(mEntry, 0x0);
}

// Inherited via IBinary

IOffsetCalculator* ELFBinary::GetOffsetCalculator()
{
    return &mDefaultCalculator;
}

ECapstoneArchMode ELFBinary::TryDeduceArchMode()
{
    auto machine = mELF->GetTargetMachine();
    ECapstoneArchMode archMode{ ECapstoneArchMode::UNDEFINED };

    switch (machine)
    {
    case EELFMachine::ARM:
    {
        if (mELF->Is64())
            archMode = ECapstoneArchMode::AARCH64_ARM;
        else
            archMode = ELFPP::ARMIsThumb(mELF.get()) ? ECapstoneArchMode::ARM32_THUMB : ECapstoneArchMode::ARM32_ARM;
        break;
    }

    default:
        break;
    }

    return archMode;
}
