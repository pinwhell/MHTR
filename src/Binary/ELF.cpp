#include <fmt/core.h>
#include <MHTR/Binary/ELF.h>
#include <MHTR/Arch/ARM/32/Resolver/FarAddress.h>
#include <MHTR/Arch/ARM/64/Resolver/FarAddress.h>
#include <CStone/Factory.h>

using namespace MHTR;

ELFBinary::ELFBinary(const void* entry, IBinaryArchModeProvider* archModeProvider)
    : mEntry(entry)
    , mELF(ELFPP::FromBuffer(mEntry))
    , mDefaultCalculator(this)
    , mArchModeProvider(archModeProvider)
{
    Map();
}

void ELFBinary::Map()
{
    if (!mELF) return;
    auto programs = mELF->GetLoadablePrograms();
    if (programs.empty()) return;

    bool bIs64 = mELF->Is64();
    auto getInfo = [&](void* p, uint64_t& vaddr, uint64_t& memsz, uint64_t& filesz, uint64_t& offset) {
        if (bIs64) {
            auto ph = (Elf64_Phdr*)p;
            vaddr = ph->p_vaddr; memsz = ph->p_memsz; filesz = ph->p_filesz; offset = ph->p_offset;
        } else {
            auto ph = (Elf32_Phdr*)p;
            vaddr = ph->p_vaddr; memsz = ph->p_memsz; filesz = ph->p_filesz; offset = ph->p_offset;
        }
    };

    // Calculate map size and virtual base
    uint64_t imageSize = mELF->GetImageSize();
    uint64_t vaddr, memsz, filesz, offset;
    getInfo(programs.front(), vaddr, memsz, filesz, offset);

    uint64_t virtualBase = (vaddr < 0x1000000) ? 0 : vaddr;
    uint64_t mapSize = imageSize;

    // Allocate with 4KB Alignment Padding
    size_t alignment = 0x1000;
    mMappedBuffer.resize(mapSize + alignment, 0);
    
    void* ptr = mMappedBuffer.data();
    size_t alignOffset = alignment - (reinterpret_cast<uintptr_t>(ptr) & (alignment - 1));
    if (alignOffset == alignment) alignOffset = 0;
    
    uint8_t* alignedPtr = (uint8_t*)ptr + alignOffset;
    
    const uint8_t* rawBase = (const uint8_t*)mEntry;
    for (void* p : programs) {
        getInfo(p, vaddr, memsz, filesz, offset);
        
        uint64_t targetOffset = vaddr - virtualBase;
        if (targetOffset + filesz <= mapSize + alignment) {
            memcpy(alignedPtr + targetOffset, rawBase + offset, filesz);
        }
    }
    
    mEntry = alignedPtr;
    mMappedSize = mapSize;
}

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

    if (machine == EELFMachine::AARCH64 && bIs64)
        return (mFarAddressResolvers[key] = std::make_unique<ARM64FarAddressResolver>(cstoneProvider)).get();
    
    return nullptr;
}

Range ELFBinary::GetRange()
{
    // Return range of the Mapped Virtual Image (Logical Size)
    return Range(mEntry, mMappedSize);
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
        archMode = ELFPP::ARMIsThumb(mELF.get()) ? ECapstoneArchMode::ARM32_THUMB : ECapstoneArchMode::ARM32_ARM;
        break;
    }

    case EELFMachine::AARCH64:
        archMode = ECapstoneArchMode::AARCH64_ARM;
        break;

    default:
        break;
    }

    return archMode;
}
