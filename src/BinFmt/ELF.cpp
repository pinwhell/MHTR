#include <BinFmt/ELF.h>
#include <CStone/Factory.h>

ELFBuffer::ELFBuffer(const BufferView& view)
    : mView(view)
    , mELF(ELFPP::FromBuffer(view.start()))
{}

std::unique_ptr<ICapstone> ELFBuffer::CreateInstance(bool bDetailedInst)
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