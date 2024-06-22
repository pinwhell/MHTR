#include <iostream>
#include <functional>
#include <filesystem>

#include <CStone/Provider.h>
#include <MHTR/Pltform.h>
#include <MHTR/IR/From/Json.h>
#include <MHTR/IR/ToMetadata.h>
#include <MHTR/Factory/MetadataTarget.h>
#include <MHTR/Metadata/Metadata.h>
#include <MHTR/Metadata/Synthers.h>
#include <MHTR/Synther/Namespace.h>
#include <MHTR/Binary/ELF.h>
#include <MHTR/Binary/Factory.h>
#include <MHTR/Binary/File.h>
#include <MHTR/Arch/ARM/32/Resolver/FarAddress.h>
#include <MHTR/PatternScan.h>
#include <MHTR/FarAddressLookup.h>
#include <MHTR/OffsetCalculator.h>
#include <MHTR/Provider/IRange.h>
#include <MHTR/Provider/ProcedureRangeChain.h>
#include <MHTR/Provider/FromFileJson.h>
#include <MHTR/Metadata/Lookups.h>

using namespace MHTR;

class IMetadataLookupContextProvider {
public:
    virtual ~IMetadataLookupContextProvider() {}
    virtual void ContextProvide(std::function<void(IOffsetCalculator*, IRangeProvider*, ICapstoneProvider*)> callback) = 0;
};

void BasicScan(IMetadataLookupContextProvider* metdtContextProvider)
{
    metdtContextProvider->ContextProvide([](IOffsetCalculator* relDispCalculator, IRangeProvider* scanRangeProvider, ICapstoneProvider* _) {
        try {
            MetadataTarget target1("Example1");
            MetadataTarget target2("Example2");
            PatternCheckLookup lookup(target1, scanRangeProvider, "7F", false);
            PatternSingleResultLookup lookup2(target2, scanRangeProvider, relDispCalculator, "7F");

            try {
                lookup.Lookup();
            }
            catch (PatternScanException& e)
            { std::cerr << e.what() << std::endl; }

            try {
                lookup2.Lookup();
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
    metdtContextProvider->ContextProvide([](IOffsetCalculator* relDispCalculator, IRangeProvider* scanRangeProvider, ICapstoneProvider* capstoneInstancer) {
        try {
            std::thread t([capstoneInstancer, scanRangeProvider] {
                Range range = scanRangeProvider->GetRange();
                // PoC Thread Safe Instancer
                ICapstone* capstone = capstoneInstancer->GetInstance();
                ICapstoneUtility* utility = capstone->getUtility();
                CapstoneDismHandle dism = capstone->Disassemble(range.GetStart<char*>() + 0x12AA, 0x1000);
                //std::cout << std::boolalpha << utility->InsnHasRegister(dism.mpFirst, ARM_REG_R0) << std::endl;
                //std::cout << utility->InsnGetImmByIndex(dism.mpFirst, 0) << std::endl;

                });

            Range range = scanRangeProvider->GetRange();
            ICapstone* capstone = capstoneInstancer->GetInstance();
            ICapstoneUtility* utility = capstone->getUtility();
            CapstoneDismHandle dism = capstone->Disassemble(range.GetStart<char*>() + 0x12AA, 0x1000);

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
    metdtContextProvider->ContextProvide([](IOffsetCalculator* relDispCalculator, IRangeProvider* scanRangeProvider, ICapstoneProvider* capstoneInstancer) {
        try {
            MetadataTarget target("Example");
            PatternScanAddresses addresses(scanRangeProvider, "?0 ?8 ?1 ?0", 0);
            InsnImmediateLookup immLookup(target, &addresses, capstoneInstancer, 0);

            immLookup.Lookup();

            auto lines = MultiNsMultiMetadataSynther({ &target }, ConstAssignSynther::Synth).Synth();

            for (const auto& line : lines)
                std::cout << line << std::endl;
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what();
        }
    });
}

void FarAddressLookupTest(IMetadataLookupContextProvider* metdtContextProvider)
{
    metdtContextProvider->ContextProvide([](IOffsetCalculator* relDispCalculator, IRangeProvider* scanRangeProvider, ICapstoneProvider* capstoneInstancer) {
        try {
            MetadataTarget target("Example");
            PatternScanAddresses addressesProvider(scanRangeProvider, "B0 BD 0C 48 40 F2", 20);
            ARM32FarAddressResolver addrResolver(capstoneInstancer);
            FarAddressLookup stackCheckGuardAddr(target, &addressesProvider, &addrResolver, relDispCalculator, false);

            stackCheckGuardAddr.Lookup();

            auto lines = MultiNsMultiMetadataSynther({ &target }, ConstAssignSynther::Synth).Synth();

            for (const auto& line : lines)
                std::cout << line << std::endl;
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what();
        }
    });
}

class TestMetadataLookupContextProvider : public IMetadataLookupContextProvider {
public:
    TestMetadataLookupContextProvider(IOffsetCalculator* relDispCalculator, IRangeProvider* rangeProvider, ICapstoneFactory* factory)
        : mRelDispCalculator(relDispCalculator)
        , mRangeProvider(rangeProvider)
        , mCapstoneProvider(factory)
    {}

    void ContextProvide(std::function<void(IOffsetCalculator*, IRangeProvider*, ICapstoneProvider*)> callback) override
    {
        callback(mRelDispCalculator, mRangeProvider, &mCapstoneProvider);
    }

private:
    IOffsetCalculator* mRelDispCalculator;
    IRangeProvider* mRangeProvider;
    CapstoneConcurrentProvider mCapstoneProvider;
};

void RunMetadataTests()
{
    try {
        std::filesystem::current_path(MHR_SAMPLES_DIR);

        BinaryFile bin("libdummy.so");
        OffsetCalculator binOffCalctor(&bin);
        TestMetadataLookupContextProvider metdtContextProvider(&binOffCalctor, &bin, &bin);

        metdtContextProvider.ContextProvide([&](IOffsetCalculator* relDispCalculator, IRangeProvider* scanRangeProvider, ICapstoneProvider* cStoneInstancer) {
            ProcedureRangeProviderChain procedureRangeProviderChain(cStoneInstancer, scanRangeProvider, {
                {PatternScanConfig("00 F0 57 B9 D0 B5 02 AF 04 46", 0), 0}  // buffView.start<uint64_t>() + 0x1AC8
                });

            procedureRangeProviderChain.GetRange();
            });

        /*FarAddressLookupTest(&metdtContextProvider);
        BasicScan(&metdtContextProvider);
        TestImmediateLookup(&metdtContextProvider);
        TestCapstone(&metdtContextProvider);*/
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

    MetadataTargetSet targets = {
        &r1,
        &r2
    };

    auto lines = MultiNsMultiMetadataSynther(targets, ConstAssignSynther::Synth).Synth();

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

#include <MHTR/Provider/Json.h>
#include <MHTR/Provider/FromJsonSingleNamespace.h>
#include <MHTR/Provider/FromJsonPathJsonFile.h>
#include <MHTR/Factory/FromTargetBinJsonBinary.h>

int TestCreationAndMetadataLookup()
{
    MetadataTargetFactory metadataTargetProvider;
    Storage<std::unique_ptr<IProvider>> scanRanges;
    Storage<std::unique_ptr<ICapstoneProvider>> cstoneProviders;
    Storage<std::unique_ptr<IBinary>> bins;

    //TestDumpMetadata();
    //TestNamespaces();
    //RunMetadataTests();

    try {
        FromFileJsonProvider targetsJsonProvider("targets.json");
        const auto& targets = (*targetsJsonProvider.GetJson());
        std::vector<std::vector<std::unique_ptr<ILookableMetadata>>> allVecLookables;

        std::transform(targets.begin(), targets.end(), std::back_inserter(allVecLookables), [&](const auto& target) {
            JsonProvider binTargetJsonProvider(target);
            FromJsonPathJsonFileProvider metadataIrJsonProvider(&binTargetJsonProvider, "metadataPath");
            FromJsonSingleNamespaceProvider nsProvider(&binTargetJsonProvider);
            FromJsonMultiMetadataIRFactory irFactory(&metadataIrJsonProvider);
            IBinary* bin = bins.Store(FromTargetBinJsonBinaryFactory(&binTargetJsonProvider).CreateBinary()).get();
            IOffsetCalculator* offsetCalculator = bin->GetOffsetCalculator();
            ICapstoneProvider* capstoneProvider = cstoneProviders.Store(std::make_unique<CapstoneConcurrentProvider>(bin)).get();

            return FromIRMultiMetadataFactory(
                scanRanges,
                &metadataTargetProvider,
                &irFactory,
                bin,
                offsetCalculator,
                capstoneProvider,
                bin,
                &nsProvider
            ).ProduceAll();
            });

        std::vector<std::unique_ptr<ILookableMetadata>> allLookables;

        for (auto& lookableVec : allVecLookables)
        {
            allLookables.reserve(allLookables.size() + lookableVec.size());
            std::move(std::make_move_iterator(lookableVec.begin()), std::make_move_iterator(lookableVec.end()), std::back_inserter(allLookables));
            lookableVec.clear();
        }

        for (auto& lookable : allLookables)
            lookable->Lookup();
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    return 0;
}

void DummyResultMake(std::function<void(const MetadataTargetSet&)> callback)
{
    Namespace fooNs("Foo");
    MetadataTarget foofooTarget("FooTarget", &fooNs); foofooTarget.TrySetResult(MetadataResult(0x10));
    MetadataTarget foobarTarget("BarTarget", &fooNs); foobarTarget.TrySetResult(MetadataResult(0x16));
    MetadataTarget foobazTarget("BazTarget", &fooNs); foobazTarget.TrySetResult(MetadataResult(0x9));

    Namespace barNs("Bar");
    MetadataTarget barfooTarget("FooTarget", &barNs); barfooTarget.TrySetResult(MetadataResult("AA ?B ?C"));
    MetadataTarget barbarTarget("BarTarget", &barNs); barbarTarget.TrySetResult(MetadataResult(0x25));
    MetadataTarget barbazTarget("BazTarget", &barNs); barbazTarget.TrySetResult(MetadataResult("AA ?B ?C"));

    MetadataTargetSet dummyResults = {
        &foofooTarget,
        &foobarTarget,
        &foobazTarget,
        &barfooTarget,
        &barbarTarget,
        &barbazTarget
    };

    callback(dummyResults);
}

template<typename JsonSynther>
class JsonAccessSynther : public ILineSynthesizer {
public:

    JsonAccessSynther(const std::string& objectName, const std::string& key, const std::string& type, bool bWrite = false)
        : mObjectName(objectName)
        , mKey(key)
        , mType(type)
        , mbWrite(bWrite)
    {}

    JsonAccessSynther(const std::string& objectName, ILineSynthesizer* key, const std::string& type, bool bWrite = false)
        : JsonAccessSynther(objectName, key->Synth(), type, bWrite)
    {}

    std::string Synth() const override
    {
        return JsonSynther::AccessSynth(mObjectName, mKey, mType, mbWrite);
    }

    std::string mObjectName;
    std::string mKey;
    std::string mType;
    bool mbWrite;
};

class AssignSynther : public ILineSynthesizer {
public:
    AssignSynther(ILineSynthesizer* lhs, ILineSynthesizer* rhs)
        : mLhs(lhs)
        , mRhs(rhs)
    {}

    std::string Synth() const override
    {
        return mLhs->Synth() + " = " + mRhs->Synth();
    }

    ILineSynthesizer* mLhs;
    ILineSynthesizer* mRhs;
};

class XoredSynther : public ILineSynthesizer {
public:
    XoredSynther(ILineSynthesizer* xoring, std::string key)
        : mXoring(xoring)
        , mKey(key)
    {}

    std::string Synth() const override
    {
        return mXoring->Synth() + " ^ " + mKey;
    }

    ILineSynthesizer* mXoring;
    std::string mKey;
};

class NlohmannJsonSynther {
public:
    static std::string GetType()
    {
        return "nlohmann::json";
    }

    static std::string GetTypeInc()
    {
        return "nlohmann/json.hpp";
    }

    static std::string AccessSynth(const std::string& objectName, const std::string& key, const std::string& type, bool bWrite = false) {
        if (bWrite)
            return objectName + "[" + key + "]";

        return objectName + "[" + key + "].get<" + type + ">()";
    }
};

class JsonCppSynther {
public:

    static std::string GetType()
    {
        return "Json::Value";
    }

    static std::string GetTypeInc()
    {
        return "json/value.h";
    }

    static std::string AccessSynth(const std::string& objectName, const std::string& key, const std::string& type, bool bWrite = false) {
        if (bWrite)
            return objectName + "[" + key + "]";

        return objectName + "[" + key + "].as<" + type + ">()";
    }
};

#include <fmt/core.h>
#include <MHTR/Synther/Cxx/Header.h>
#include <MHTR/Synther/MultiLineSingleLine.h>

int main(int argc, const char* argv[])
{
    std::filesystem::current_path(MHR_SAMPLES_DIR);

    DummyResultMake([](const MetadataTargetSet& results) {
        CxxHeaderHead head; head
            .GetIncBlockBuilder()
            ->Add("cstdint")
            ->Add("MHTRSDK.h")
            ->Add(NlohmannJsonSynther::GetTypeInc());

        MultiNsMultiMetadataSynther bodySynther(results, [](const std::string& ns, const MetadataTargetSet& targets, const Indent& indent) {
            MultiLine allTargetsAssign;
            allTargetsAssign.emplace_back("MHTR::MetadataProvider all;");
            std::transform(targets.begin(), targets.end(), std::back_inserter(allTargetsAssign), [](MetadataTarget* target) {
                std::string type = std::holds_alternative<PatternMetadata>(target->mResult.mMetadata) ? "std::string" : "uint64_t";
                JsonAccessSynther<NlohmannJsonSynther> targetJsonAccess("json", Literal(target->GetFullName()), type, false);
                Line providerWrite("all[" + Literal(target->GetFullName()) + "]");
                XoredSynther targetJsonAccessXored(&targetJsonAccess, "0x0");
                return AssignSynther(&providerWrite, &targetJsonAccessXored).Synth();
                });   
            allTargetsAssign.emplace_back("return all;");
            LineGroup allTargetsAssignGroup(allTargetsAssign);
            Line fnArg("const " + NlohmannJsonSynther::GetType() + "& json");
            return MetadataProviderFunction(ns + "Create", &allTargetsAssignGroup, &fnArg).Synth();
            });

        const auto all = MultiLineSynthesizerGroup({
            &head,
            &MultiLineSingleLine::mEmptyLine,
            &bodySynther
            }).Synth();

        for(const auto& one : all)
            std::cout << one << std::endl;
        });

    return 0;
}
