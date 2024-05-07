#include <Metadata.h>
#include <iostream>

#include <FileBufferView.h>

#include <capstone/capstone.h>
#include <ELFPP.hpp>
#include <fmt/core.h>
#include <TBS.hpp>
#include <PatternScan.h>
#include <BinFmt/ELF.h>
#include <CStone/CStone.h>

template<typename ResultT, typename T>
ResultT ARM32PCFollow(ICapstone* capstone, T at, uint64_t disp = 0)
{
    auto dism = capstone->Disassemble((char*)at, 4 * 2, (uint64_t)at);

    if (dism.mCount < 2)
        throw std::runtime_error(fmt::format("PC Follow {}: 2 instrunction disassembly failed", fmt::ptr((char*)at)));

    return  (ResultT) ((char*)at + disp + (dism.mpFirst[0].size + dism.mpFirst[1].size));
}

template<typename ResultT, typename T>
ResultT ARM32LDRPCDispFollow(ICapstone* capstone, T at, bool bDerref = false)
{
    const void* _at = (const void*)at;

    CsInsn insn = capstone->DisassembleOne(_at);

    if (insn->id != ARM_INS_LDR)
        throw std::runtime_error(fmt::format("LEAPCDisp Follow '{} {}': unexpected instruction", insn->mnemonic, insn->op_str));

    auto& memOp = insn->detail->arm.operands[1];

    if (memOp.type != CS_OP_MEM ||
        memOp.mem.index != ARM_REG_INVALID)
        throw std::runtime_error(fmt::format("LEAPCDisp Follow '{} {}': unexpected instruction format", insn->mnemonic, insn->op_str));

    uint64_t followAddr = ARM32PCFollow<uint64_t>(capstone, at, memOp.mem.disp);

    if (bDerref)
        return (ResultT)(*(uint32_t*)followAddr);

    return (ResultT)(followAddr);
}

/*LEA => Load Effective Address*/
template<typename ResultT, typename T>
ResultT ARM32LDRLongLEATryFollow(ICapstone* capstone, T at, bool bDerref = false)
{
    uint32_t pcRelDisp = ARM32LDRPCDispFollow<uint32_t>(capstone, at, true);
    CsInsn ldrInsn = capstone->DisassembleOne((const void*)at);
    ICapstoneUtility* utility = capstone->getUtility();
    auto Rd = utility->InsnGetPseudoDestReg(&ldrInsn.mInsn);
    bool bFound = false;
    ResultT res{};
    const void* nextInsnStart = (const char*)at + ldrInsn->size;

    capstone->InsnForEach(nextInsnStart, [&](const CsInsn& insn) {
        if (!utility->InsnHasRegister(&insn.mInsn, Rd))
            return true;

        if (!utility->InsnHasRegister(&insn.mInsn, ARM_REG_PC))
            return true;

        const void* followRes = ARM32PCFollow<const void*>(capstone, insn->address, pcRelDisp);

        res = bDerref ? (ResultT)(const void*)(*(uint32_t*)followRes) : (ResultT)followRes;

        return !(bFound = true);
        }, SIZE_MAX, (uint64_t)nextInsnStart);

    if (!bFound)
        throw std::runtime_error(fmt::format("'{} {}' not found finalizer", ldrInsn->mnemonic, ldrInsn->op_str));

    return res;
}



void BasicScan()
{
    try {
        FileView fileView("libdrm.so");
        BufferView buffView = BufferViewFromFileView(fileView);
        MetadataTarget target("Example");
        PatternCheckLookup lookup(target, buffView, "4D 5A", false);
        PatternSingleResultLookup lookup2(target, buffView, "4D 5A");

        try {
            lookup.Lookup();
            std::cout << lookup.mTarget.mResult.mPattern.mValue << std::endl;
        }
        catch (PatternScanException& e)
        {
            std::cerr << e.what();
        }

        try {
            lookup2.Lookup();
            std::cout << std::hex << lookup2.mTarget.mResult.mOffset.mValue << std::endl;
        }
        catch (PatternScanException& e)
        {
            std::cerr << e.what();
        }

        return;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what();
    }
}

void RawELF()
{
    try {
        FileView fileView("libdrm.so");
        BufferView buffView = BufferViewFromFileView(fileView);
        ELFBuffer ELFBuffer(buffView);
        ELFPP::IELF& elf = *(ELFBuffer.mELF);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what();
    }
}

class ICapstoneInstanceProvider {
public:
    virtual ICapstone* GetInstance(bool bDetailedInstuction = true, ICapstoneFactory* _factory = nullptr) = 0;
};

class CapstoneTSafeInstanceProvider : public ICapstoneInstanceProvider {
public:
    CapstoneTSafeInstanceProvider(ICapstoneFactory* defFactory = nullptr)
        : mDefaultFactory(defFactory)
    {}

    ICapstone* GetInstance(bool bDetailedInstuction = true, ICapstoneFactory* _factory = nullptr) override
    {
        std::thread::id this_id = std::this_thread::get_id();

        std::unique_lock<std::mutex> lock(mMutex);
        while (mInstances.find(this_id) == mInstances.end()) {
            ICapstoneFactory* factory = _factory ? _factory : mDefaultFactory;

            if (factory == nullptr)
                return nullptr;

            // This thread doesn't have a Capstone object yet, so create one.
            mInstances[this_id] = factory->CreateCapstoneInstance(bDetailedInstuction);
        }

        return mInstances[this_id].get();
    }

    std::mutex mMutex;
    std::unordered_map<std::thread::id, std::unique_ptr<ICapstone>> mInstances;
    ICapstoneFactory* mDefaultFactory;
};

void TestCapstone()
{
    try {
        FileView fileView("libdummy.so");
        BufferView buffView = BufferViewFromFileView(fileView);
        ELFBuffer ELFBuffer(buffView);
        CapstoneTSafeInstanceProvider capstoneInstanceProvider(&ELFBuffer);

        std::thread t([&capstoneInstanceProvider, &buffView] {
            // PoC Thread Safe Instancer

            ICapstone* capstone = capstoneInstanceProvider.GetInstance();
            ICapstoneUtility* utility = capstone->getUtility();
            CapstoneDismHandle dism = capstone->Disassemble(buffView.start<char*>() + 0x12AA, 0x1000);
            //std::cout << std::boolalpha << utility->InsnHasRegister(dism.mpFirst, ARM_REG_R0) << std::endl;
            //std::cout << utility->InsnGetImmByIndex(dism.mpFirst, 0) << std::endl;

            });

        ICapstone* capstone = capstoneInstanceProvider.GetInstance();
        ICapstoneUtility* utility = capstone->getUtility();
        CapstoneDismHandle dism = capstone->Disassemble(buffView.start<char*>() + 0x12AA, 0x1000);

        utility->InsnHasRegister(dism.mpFirst, ARM_REG_R0);
        utility->InsnGetImmByIndex(dism.mpFirst, 0);

		if (t.joinable())
            t.join(); // Wait thread finish

        std::cout << fmt::format(
            "{}\n",
            fmt::ptr(
                (void*)buffView.OffsetFromBase(
                    ARM32LDRLongLEATryFollow<uint64_t>(
                        capstone,
                        buffView.start<char*>() + 0x1BAC
                    )
                )
            )
        );
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what();
    }
}

void TestImmediateLookup()
{
    try {
        FileView fileView("libdummy.so");
        BufferView buffView = BufferViewFromFileView(fileView);
        ELFBuffer ELFBuffer(buffView);
        std::unique_ptr<ICapstone> capstone = ELFBuffer.CreateCapstoneInstance();
        MetadataTarget target("Example");
        PatternScanAddresses addresses(buffView, "?0 ?8 ?1 ?0", 0);
        InsnImmediateLookup immLookup(target,&addresses, &buffView, capstone.get(), 0);
        immLookup.Lookup();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what();
    }
}

int main(int argc, const char** argv)
{
    std::filesystem::current_path(MHR_SAMPLES_DIR);

    //TestImmediateLookup();
    TestCapstone();

	return 1;
}

CsInsn::CsInsn()
{
    memset(&mInsn, 0x0, sizeof(mInsn));
    memset(&mDetail, 0x0, sizeof(mDetail));
    mInsn.detail = &mDetail;
}

const cs_insn* CsInsn::operator->() const
{
    return &mInsn;
}

ELFBuffer::ELFBuffer(const BufferView& view)
    : mView(view)
    , mELF(ELFPP::FromBuffer(view.start()))
{}

std::unique_ptr<ICapstone> ELFBuffer::CreateCapstoneInstance(bool bDetailedInst)
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

    return CapstoneFactory(archMode).CreateCapstoneInstance(bDetailedInst);
}
