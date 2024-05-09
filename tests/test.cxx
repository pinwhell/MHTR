#include <iostream>
#include <fmt/core.h>

#include <Metadata.h>

#include <FileBufferView.h>
#include <PatternScan.h>

#include <BinFmt/ELF.h>

#include <CStone/CStone.h>
#include <CStone/Factory.h>
#include <CStone/Provider.h>
#include <CStone/Arch/ARM/32/Capstone.h>

#include <Arch/ARM/32/FarAddressResolver.h>

#include <FarAddressLookup.h>
#include <RangeProvider.h>
#include <ProcedureRangeProvider.h>
#include <AsmExtractedProcedureEntryProvider.h>

#include <MultiException.h>

class IMetadataLookupContextProvider {
public:
    virtual void ContextProvide(std::function<void(BufferView&, ICapstoneInstanceProvider*)> callback) = 0;
};

void BasicScan(IMetadataLookupContextProvider* metdtContextProvider)
{
    metdtContextProvider->ContextProvide([](BufferView& buffView, ICapstoneInstanceProvider* _) {
        try {
            MetadataTarget target1("Example1");
            MetadataTarget target2("Example2");
            PatternCheckLookup lookup(target1, buffView, "7F", false);
            PatternSingleResultLookup lookup2(target2, buffView, "7F");

            try {
                lookup.Lookup();
                std::cout << lookup.mTarget.mResult.mPattern.mValue << std::endl;
            }
            catch (PatternScanException& e)
            { std::cerr << e.what() << std::endl; }

            try {
                lookup2.Lookup();
                std::cout << std::hex << lookup2.mTarget.mResult.mOffset.mValue << std::endl;
            }
            catch (PatternScanException& e)
            { std::cerr << e.what() << std::endl; }
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what();
        }
    });
}

void TestCapstone(IMetadataLookupContextProvider* metdtContextProvider)
{
    metdtContextProvider->ContextProvide([](BufferView& buffView, ICapstoneInstanceProvider* capstoneInstancer) {
        try {
            std::thread t([capstoneInstancer, &buffView] {
                // PoC Thread Safe Instancer

                ICapstone* capstone = capstoneInstancer->GetInstance();
                ICapstoneUtility* utility = capstone->getUtility();
                CapstoneDismHandle dism = capstone->Disassemble(buffView.start<char*>() + 0x12AA, 0x1000);
                //std::cout << std::boolalpha << utility->InsnHasRegister(dism.mpFirst, ARM_REG_R0) << std::endl;
                //std::cout << utility->InsnGetImmByIndex(dism.mpFirst, 0) << std::endl;

                });

            ICapstone* capstone = capstoneInstancer->GetInstance();
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
                        (uint64_t)ARM32FarPcRelLEATryResolve(
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
    });
}

void TestImmediateLookup(IMetadataLookupContextProvider* metdtContextProvider)
{
    metdtContextProvider->ContextProvide([](BufferView& buffView, ICapstoneInstanceProvider* capstoneInstancer) {
        try {
            ICapstone* capstone = capstoneInstancer->GetInstance();
            MetadataTarget target("Example");
            RangeProvider rangeProvider(buffView);
            PatternScanAddresses addresses(&rangeProvider, "?0 ?8 ?1 ?0", 0);
            InsnImmediateLookup immLookup(target, &addresses, &buffView, capstone, 0);
            immLookup.Lookup();
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what();
        }
    });
}

void FarAddressLookupTest(IMetadataLookupContextProvider* metdtContextProvider)
{
    metdtContextProvider->ContextProvide([](BufferView& buffView, ICapstoneInstanceProvider* capstoneInstancer) {
        try {
            ICapstone* capstone = capstoneInstancer->GetInstance();
            MetadataTarget target("Example");
            RangeProvider rangeProvider(buffView);
            PatternScanAddresses addressesProvider(&rangeProvider, "B0 BD 0C 48 40 F2", 20);
            ARM32FarAddressResolver addrResolver(capstone);
            FarAddressLookup stackCheckGuardAddr(target, &addressesProvider, &addrResolver, &buffView, false);

            stackCheckGuardAddr.Lookup();

            std::cout << std::hex << stackCheckGuardAddr.mTarget.mResult.mOffset << std::endl;
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what();
        }
    });
}

class TestMetadataLookupContextProvider : public IMetadataLookupContextProvider {
public:
    TestMetadataLookupContextProvider(const BufferView& buffView, ICapstoneFactory* factory)
        : mBuffView(buffView)
        , mCapstoneInstanceProvider(factory)
    {}

    void ContextProvide(std::function<void(BufferView&, ICapstoneInstanceProvider*)> callback)
    {
        callback(mBuffView, &mCapstoneInstanceProvider);
    }

private:
    BufferView mBuffView;
    CapstoneConcurrentInstanceProvider mCapstoneInstanceProvider;
};

int main(int argc, const char** argv)
{
    try {
        std::filesystem::current_path(MHR_SAMPLES_DIR);

        FileBufferView fileView("libdummy.so");
        ELFBuffer EflBuffer(fileView.mBufferView);
        TestMetadataLookupContextProvider metdtContextProvider(fileView.mBufferView, &EflBuffer);

        metdtContextProvider.ContextProvide([&](BufferView& buffView, ICapstoneInstanceProvider* cStoneInstancer) {
            ICapstone* capstone = cStoneInstancer->GetInstance();
            RangeProvider scanRange(buffView);
            PatternScanAddresses procAddresses(&scanRange, "00 F0 57 B9 D0 B5 02 AF 04 46");
            AsmExtractedProcedureEntryProvider entryProvider(capstone, &procAddresses);
            ProcedureRangeProvider range(capstone, &entryProvider); // buffView.start<uint64_t>() + 0x1AC8

            range.GetRange();
            });

        //FarAddressLookupTest(&metdtContextProvider);
        //BasicScan(&metdtContextProvider);
        //TestImmediateLookup(&metdtContextProvider);
        //TestCapstone(&metdtContextProvider);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    return 0;
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

MultiException::MultiException(const std::vector<std::string>& exceptions)
    : std::runtime_error(""), mExceptions(exceptions) {}

const char* MultiException::what() const noexcept {
    std::stringstream ss;

    for (size_t i = 0; i < mExceptions.size(); ++i)
        ss << "\n" << mExceptions[i];

    mFullException = ss.str();

    return mFullException.c_str();
}

FarAddressLookup::FarAddressLookup(MetadataTarget& target, IAddressesProvider* insnAddrsProvider, IFarAddressResolver* farAddrResolver, IRelativeDispProvider* dispCalculator, bool bDeref)
    : mTarget(target)
    , mInsnAddressesProvider(insnAddrsProvider)
    , mFarAddressResolver(farAddrResolver)
    , mDispCalculator(dispCalculator)
    , mDeref(bDeref)
{}

void FarAddressLookup::Lookup()
{
    if (mTarget.ResultIsFound())
        return;

    std::vector<uint64_t> insnAddresses = mInsnAddressesProvider->GetAllAddresses();
    std::unordered_set<uint64_t> addrRes;

    std::vector<std::string> errs;

    for (const auto insnAddr : insnAddresses)
    {
        try {
            auto farAddr = mFarAddressResolver->TryResolve(insnAddr, mDeref);
            addrRes.insert(mDispCalculator->OffsetFromBase(farAddr));
        }
        catch (const std::exception& e)
        {
            errs.push_back(e.what());
        }
    }

    if (addrRes.size() < 1)
    {
        if (errs.empty())
            throw MetadataLookupException(fmt::format("'{}' no far-addresses found.", mTarget.mName));
        else
            throw MetadataLookupException(fmt::format("'{}' {}", mTarget.mName, MultiException(errs).what()));
    }

    if (addrRes.size() > 1)
        throw MetadataLookupException(fmt::format("'{}' multiple diferent far-addresses found.", mTarget.mName));

    mTarget.TrySetResult(MetadataResult(*addrRes.begin()));
}

ARM32FarAddressResolver::ARM32FarAddressResolver(ICapstone* capstone)
    : mCapstone(capstone)
{}

uint64_t ARM32FarAddressResolver::TryResolve(uint64_t at, bool bDerref)
{
    return (uint64_t)ARM32FarPcRelLEATryResolve(mCapstone, (void*)at, bDerref);
}

ProcedureRangeProvider::ProcedureRangeProvider(ICapstone* capstone, IProcedureEntryProvider* procEntryProvider)
    : mCapstone(capstone)
    , mProcEntryProvider(procEntryProvider)
{}

BufferView ProcedureRangeProvider::GetRange() {
    uint64_t procEntry = mProcEntryProvider->GetEntry();
    uint64_t procEnd = 0;
    ICapstoneHeuristic* heuristic = mCapstone->getHeuristic();

    mCapstone->InsnForEach((void*)procEntry, [&](const CsInsn& curr) {
        auto currDisp = curr->address;
        uint64_t currAddr = procEntry + currDisp;

        procEnd = currAddr + curr->size;

        if (heuristic->InsnIsProcedureEntry(&curr.mInsn) && currDisp)
        {
            // At this point, seems current instruciton 
            // is a procedure entry from anoter procedure
            // probably we missed the epilog of the 
            // mProcEntry or, it didnt have any, 
            // just like the case of non-return functions

            return false;
        }

        return heuristic->InsnIsProcedureExit(&curr.mInsn) == false;
        }, 0);

    if (!procEnd)
        throw std::runtime_error("procedure end lookup failed");

    return BufferView((void*)procEntry, procEnd - procEntry);
}

AsmExtractedProcedureEntryProvider::AsmExtractedProcedureEntryProvider(ICapstone* capstone, IAddressesProvider* adressesProvider)
    : mCapstone(capstone)
    , mAddressesProvider(adressesProvider)
{}

uint64_t AsmExtractedProcedureEntryProvider::GetEntry()
{
    std::vector<uint64_t> addresses = mAddressesProvider->GetAllAddresses();
    std::unordered_set<uint64_t> procAddresses;

    ICapstoneUtility* utility = mCapstone->getUtility();

    std::vector<std::string> allErrs;

    for (const auto addr : addresses)
    {
        try {
            auto insn = mCapstone->DisassembleOne((void*)addr, 0);

            if (utility->InsnIsBranch(&insn.mInsn) == false)
            {
                // Treating the address as 
                // a normal procedure entry

                procAddresses.insert(addr);
                continue;
            }

            // Seems to be a type of branch. 
            // lets extract the disp

            uint64_t callDisp = utility->InsnGetImmByIndex(&insn.mInsn, 0);
            uint64_t callDst = addr + callDisp;

            // Successfully solved, saving

            procAddresses.insert(callDst);

        }
        catch (std::exception& e)
        {
            allErrs.push_back(e.what());
        }
    }

    if (procAddresses.size() > 1)
        throw "multiple procedure entry found";

    if (procAddresses.size() < 1)
        throw MultiException(allErrs);

    return *procAddresses.begin();
}

RangeProvider::RangeProvider(const BufferView& buffView)
    : mBuffView(buffView)
{}

BufferView RangeProvider::GetRange()
{
    return mBuffView;
}