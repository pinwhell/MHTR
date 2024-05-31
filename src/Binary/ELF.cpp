#include <Binary/ELF.h>
#include <CStone/Factory.h>
#include <fmt/core.h>
#include <Arch/ARM/32/Resolver/FarAddress.h>

ELFBinary::ELFBinary(const void* entry)
    : mEntry(entry)
    , mELF(ELFPP::FromBuffer(mEntry))
    , mDefaultCalculator(this)
{}

std::unique_ptr<ICapstone> ELFBinary::CreateInstance(bool bDetailedInst)
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
