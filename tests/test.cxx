#include <iostream>
#include <filesystem>

#include <fmt/core.h>
#include <BinFmt/ELF.h>
#include <Provider/Range.h>
#include <Provider/AsmExtractedProcedureEntry.h>
#include <Provider/ProcedureRange.h>
#include <CStone/Provider.h>
#include <Arch/ARM/32/Resolver/FarAddress.h>
#include <Synther/Namespace.h>

#include <Metadata.h>
#include <PatternScan.h>
#include <FileBufferView.h>
#include <FarAddressLookup.h>
#include <MetadataSynthers.h>

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

            //std::cout << fmt::format(
            //    "{}\n",
            //    fmt::ptr(
            //        (void*)buffView.OffsetFromBase(
            //            (uint64_t)ARM32FarPcRelLEATryResolve(
            //                capstone,
            //                buffView.start<char*>() + 0x1BAC
            //            )
            //        )
            //    )
            //);
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
            MetadataTarget target("Example");
            ICapstone* capstone = capstoneInstancer->GetInstance();
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

            auto lines = MultiNsMultiMetadataStaticSynther({ &target }).Synth();

            for (const auto& line : lines)
                std::cout << line << std::endl;

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

void RunMetadataTests()
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
}

void TestDumpMetadata()
{
    Namespace n1("Foo");
    Namespace n2("Bar");

    MetadataTarget r1("foo", &n1); r1.TrySetResult(MetadataResult("AA BB CC"));
    MetadataTarget r2("bar", &n2); r2.TrySetResult(MetadataResult(0x10));

    std::vector<MetadataTarget*> targets{
        &r1,
        &r2
    };

    auto lines = MultiNsMultiMetadataStaticSynther(targets).Synth();

    for (const auto& line : lines)
        std::cout << line << std::endl;
}

void TestNamespaces()
{
    Namespace outer("Outer");
    Namespace inner("Inner", &outer);
    Namespace bar("Bar", &inner);
    Namespace foo("Foo", &bar);
    NamespacedIdentifier baz("baz", &foo);

    std::cout << baz.GetFullIdentifier(true) << std::endl;
}

int main(int argc, const char** argv)
{
    //TestDumpMetadata();
    //TestNamespaces();
    //RunMetadataTests();


    return 0;
}