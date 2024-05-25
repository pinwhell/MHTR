#include <iostream>
#include <filesystem>
#include <deque>

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
#include <Storage.h>
#include <PatternScanConfig.h>
#include <nlohmann/json.hpp>
#include <IR/Metadata.h>
#include <IR/From/Json.h>
#include <Exception/UnexpectedLayout.h>

class IMetadataLookupContextProvider {
public:
    virtual void ContextProvide(std::function<void(IRelativeDispProvider*, IRangeProvider*, ICapstoneProvider*)> callback) = 0;
};

void BasicScan(IMetadataLookupContextProvider* metdtContextProvider)
{
    metdtContextProvider->ContextProvide([](IRelativeDispProvider* relDispCalculator, IRangeProvider* scanRangeProvider, ICapstoneProvider* _) {
        try {
            MetadataTarget target1("Example1");
            MetadataTarget target2("Example2");
            PatternCheckLookup lookup(target1, scanRangeProvider, "7F", false);
            PatternSingleResultLookup lookup2(target2, scanRangeProvider, "7F");

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
    metdtContextProvider->ContextProvide([](IRelativeDispProvider* relDispCalculator, IRangeProvider* scanRangeProvider, ICapstoneProvider* capstoneInstancer) {
        try {
            BufferView bv = scanRangeProvider->GetRange();

            std::thread t([capstoneInstancer, &bv] {
                // PoC Thread Safe Instancer
                ICapstone* capstone = capstoneInstancer->GetInstance();
                ICapstoneUtility* utility = capstone->getUtility();
                CapstoneDismHandle dism = capstone->Disassemble(bv.start<char*>() + 0x12AA, 0x1000);
                //std::cout << std::boolalpha << utility->InsnHasRegister(dism.mpFirst, ARM_REG_R0) << std::endl;
                //std::cout << utility->InsnGetImmByIndex(dism.mpFirst, 0) << std::endl;

                });

            ICapstone* capstone = capstoneInstancer->GetInstance();
            ICapstoneUtility* utility = capstone->getUtility();
            CapstoneDismHandle dism = capstone->Disassemble(bv.start<char*>() + 0x12AA, 0x1000);

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
    metdtContextProvider->ContextProvide([](IRelativeDispProvider* relDispCalculator, IRangeProvider* scanRangeProvider, ICapstoneProvider* capstoneInstancer) {
        try {
            MetadataTarget target("Example");
            PatternScanAddresses addresses(scanRangeProvider, "?0 ?8 ?1 ?0", 0);
            InsnImmediateLookup immLookup(target, &addresses, capstoneInstancer, 0);

            immLookup.Lookup();

            auto lines = MultiNsMultiMetadataStaticSynther({ &target }).Synth();

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
    metdtContextProvider->ContextProvide([](IRelativeDispProvider* relDispCalculator, IRangeProvider* scanRangeProvider, ICapstoneProvider* capstoneInstancer) {
        try {
            MetadataTarget target("Example");
            PatternScanAddresses addressesProvider(scanRangeProvider, "B0 BD 0C 48 40 F2", 20);
            ARM32FarAddressResolver addrResolver(capstoneInstancer);
            FarAddressLookup stackCheckGuardAddr(target, &addressesProvider, &addrResolver, relDispCalculator, false);

            stackCheckGuardAddr.Lookup();

            auto lines = MultiNsMultiMetadataStaticSynther({ &target }).Synth();

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
    TestMetadataLookupContextProvider(IRelativeDispProvider* relDispCalculator, IRangeProvider* rangeProvider, ICapstoneFactory* factory)
        : mRelDispCalculator(relDispCalculator)
        , mRangeProvider(rangeProvider)
        , mCapstoneProvider(factory)
    {}

    void ContextProvide(std::function<void(IRelativeDispProvider*, IRangeProvider*, ICapstoneProvider*)> callback) override
    {
        callback(mRelDispCalculator, mRangeProvider, &mCapstoneProvider);
    }

private:
    IRelativeDispProvider* mRelDispCalculator;
    IRangeProvider* mRangeProvider;
    CapstoneConcurrentProvider mCapstoneProvider;
};

class ProcedureRangeProviderChain : public IRangeProvider {
public:
    ProcedureRangeProviderChain(ICapstoneProvider* cstoneInstanceProvider, IRangeProvider* baseRangeProvider, const std::vector<PatternScanConfig>& nestedProcedurePatterns)
    {
        mpRangeProviders.emplace_back(baseRangeProvider);

        for (const auto& procPatternCfg : nestedProcedurePatterns)
        {
            auto addressesProv = (IAddressesProvider*)mProviders.Store(
                std::make_unique<PatternScanAddresses>(mpRangeProviders.back(), procPatternCfg)
            ).get();

            auto procEntryProv = (IProcedureEntryProvider*)mProviders.Store(
                std::make_unique<AsmExtractedProcedureEntryProvider>(cstoneInstanceProvider, addressesProv)
            ).get();

            auto procRangeProv = (IRangeProvider*)mProviders.Store(
                std::make_unique<ProcedureRangeProvider>(cstoneInstanceProvider, procEntryProv)
            ).get();

            mpRangeProviders.push_back(procRangeProv);
        }
    }

    BufferView GetRange() override
    {
        return mpRangeProviders.back()->GetRange();
    }

    Storage<std::unique_ptr<IProvider>> mProviders;
    std::vector<IRangeProvider*> mpRangeProviders;
};

void RunMetadataTests()
{
    try {
        std::filesystem::current_path(MHR_SAMPLES_DIR);

        FileBufferView fileView("libdummy.so");
        ELFBuffer EflBuffer(fileView.mBufferView);
        TestMetadataLookupContextProvider metdtContextProvider(&fileView, &fileView, &EflBuffer);

        metdtContextProvider.ContextProvide([&](IRelativeDispProvider* relDispCalculator, IRangeProvider* scanRangeProvider, ICapstoneProvider* cStoneInstancer) {
            ProcedureRangeProviderChain procedureRangeProviderChain(cStoneInstancer, scanRangeProvider, {
                PatternScanConfig("00 F0 57 B9 D0 B5 02 AF 04 46", 0)  // buffView.start<uint64_t>() + 0x1AC8
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

class IMetadataTargetProvider {
public:
    virtual MetadataTarget* GetMetadataTarget(const std::string& name, INamespace* ns = nullptr) = 0;
};

// Flygweight Metadata Target Factory Owninig & Providing
// Centralized access to Metadata Targets

class MetadataTargetFactory : public IMetadataTargetProvider {
private:
    // a map perfectly mapping the fully qualified name 
    // from the metadata target to its metadata target object

    std::unordered_map<std::string, std::unique_ptr<MetadataTarget>> mMetadataTargetMap;

    MetadataTarget* GetMetadataTarget(const std::string& name, INamespace* ns = nullptr) override
    {
        std::string fullyQualifiedName = fmt::format("{}{}", ns ? ns->GetNamespace() + "::" : "", name);

        if (mMetadataTargetMap.find(fullyQualifiedName) != mMetadataTargetMap.end())
            return mMetadataTargetMap[fullyQualifiedName].get();

        mMetadataTargetMap[fullyQualifiedName] = std::make_unique<MetadataTarget>(name, ns);

        return mMetadataTargetMap[fullyQualifiedName].get();
    }
};

class FromIR2MetadataFactory {
public:
    FromIR2MetadataFactory(
        Storage<std::unique_ptr<IProvider>>& providersStorage,
        IMetadataTargetProvider* metadataTargetProvider,
        IMultiMetadataIRProvider* metadataIRProvider,
        IRangeProvider* defaultScanRange,
        ICapstoneProvider* capstoneProvider,
        INamespace* ns = nullptr
    )
        : mProvidersStorage(providersStorage)
        , mMetadataTargetProvider(metadataTargetProvider)
        , mMetadataIRProvider(metadataIRProvider)
        , mDefaultScanRange(defaultScanRange)
        , mCapstoneProvider(capstoneProvider)
        , mNs(ns)
    {}

    std::vector<std::unique_ptr<ILookableMetadata>> ProduceAll() {
        std::vector<MetadataIR> allMetadata = mMetadataIRProvider->GetAllMetadatas();

        for (MetadataIR& metadata : allMetadata)
        {
            if (metadata.mType != EMetadata::METADATA_SCAN_RANGE)
                continue;

            CreateMetadataScanRangeFromIR(metadata);
        }

        std::vector<std::unique_ptr<ILookableMetadata>> result;

        for (MetadataIR& metadata : allMetadata)
        {
            if (metadata.mType != EMetadata::METADATA_LOOKUP)
                continue;

            result.emplace_back(std::move(CreateMetadataLookupFromIR(metadata)));
        }

        return result;
    }

    Storage<std::unique_ptr<IProvider>>& mProvidersStorage;
    IMetadataTargetProvider* mMetadataTargetProvider;
    IMultiMetadataIRProvider* mMetadataIRProvider;
    IRangeProvider* mDefaultScanRange;
    ICapstoneProvider* mCapstoneProvider;
    INamespace* mNs;

    // Internal
    std::unordered_map<std::string, IRangeProvider*> mRangeProviderMap;

private:
    MetadataTarget* MetadataTargetFromIR(MetadataTargetIR& ir)
    {
        return mMetadataTargetProvider->GetMetadataTarget(ir.mName, mNs);
    }

    std::unique_ptr<ILookableMetadata> CreateMetadataLookupFromIR(MetadataIR& ir)
    {
        MetadataTarget& target = *MetadataTargetFromIR(ir.mTarget);

        const auto& lookup = *ir.mLookup;

        if (lookup.mType == EMetadataLookup::PATTERN_VALIDATE)
            return CreatePatternValidateLookupFromIR(target, *lookup.mPatternValidate);

        if (lookup.mType == EMetadataLookup::INSN_IMMEDIATE)
            return CreateInsnImmLookupFromIR(target, *lookup.mInsnImmediate);

        return 0;
    }

    std::unique_ptr<ILookableMetadata> CreatePatternValidateLookupFromIR(MetadataTarget& target, PatternValidateLookupIR& ir)
    {
        IRangeProvider* scanRange = CreateScanRangeFromIR(ir.mScanRange);

        return std::make_unique<PatternCheckLookup>(target, scanRange, ir.mPattern, ir.mbUnique);
    }

    std::unique_ptr<ILookableMetadata> CreateInsnImmLookupFromIR(MetadataTarget& target, InsnImmediateLookupIR& ir)
    {
        auto& scanCombo = ir.mScanCombo;
        auto& scanCFG = scanCombo.mScanCFG;

        IRangeProvider* scanRange = CreateScanRangeFromIR(scanCombo.mScanRange);
        IAddressesProvider* addressesProvider = (IAddressesProvider*) mProvidersStorage.Store(
            std::make_unique<PatternScanAddresses>(
                scanRange,
                PatternScanConfig(
                    scanCFG.mPattern,
                    scanCFG.mDisp
                )
            )
        ).get();

        return std::make_unique<InsnImmediateLookup>(target, addressesProvider, mCapstoneProvider, ir.mImmIndex);
    }

    IRangeProvider* CreateMetadataScanRangeFromIR(MetadataIR& ir)
    {
        if(mRangeProviderMap.find(ir.mTarget.mName) != mRangeProviderMap.end())
            throw UnexpectedLayoutException(fmt::format("'{}':Metadata Scan Range duplicated detected."));

        return mRangeProviderMap[ir.mTarget.mName] = CreateScanRangeFromIR(ir.mScanRange->mScanRange);
    }

    IRangeProvider* CreateScanRangeFromIR(ScanRangeIR& ir)
    {
        if (ir.mType == EMetadataScanRange::DEFAULT)
            return mDefaultScanRange;

        if (ir.mType == EMetadataScanRange::REFERENCE)
        {
            auto& key = *ir.mRef;

            if (mRangeProviderMap.find(key) == mRangeProviderMap.end())
                throw UnexpectedLayoutException(fmt::format("'{}':Scan Range Reference not found."));

            return mRangeProviderMap[key];
        }

        return CreateScanRangePipelineFromIR(*ir.mPipeline);
    }

    IRangeProvider* CreateScanRangePipelineFromIR(MetadataScanRangePipelineIR& pipeline)
    {
        std::vector<PatternScanConfig> configs;

        for (const auto& stage : pipeline.mStages)
        {
            const auto& scanCFG = stage.mFunction->mScanCFG;

            configs.emplace_back(std::move(PatternScanConfig(
                scanCFG.mPattern,
                scanCFG.mDisp
            )));
        }

        return (IRangeProvider*) mProvidersStorage.Store(std::make_unique<ProcedureRangeProviderChain>(mCapstoneProvider, mDefaultScanRange, configs)).get();
    }
};

int main(int argc, const char** argv)
{
    std::filesystem::current_path(MHR_SAMPLES_DIR);

    //TestDumpMetadata();
    //TestNamespaces();
    //RunMetadataTests();

    FromJsonMultiMetadataIRProvider multiMetadataProvider(R"(
    [
        {
            "name" : "Bar",               
            "scanRange" : [             
                {
                    "defFnSize" : 10,   
                    "pattern" : {
                        "pattern" : "AA BB C? D? ? E?",
                        "disp" : -10    
                    }
                },
                {
                    "defFnSize" : 10,   
                    "pattern" : {
                        "pattern" : "AA BB C? D? ? E?",
                        "disp" : -10    
                    }
                }
            ]
        },
        {
            "name" : "Foo",
            "type" : "INSN_IMM",        
            "immIndex" : 1,             
            "pattern" : "AA BB CC",
            "disp" : -5,               
 
            "scanRange" : "Bar"
        }
    ]
)");

    try {
        FileBufferView fileView("libdummy.so");
        ELFBuffer elfBuffer(fileView.mBufferView);
        CapstoneConcurrentProvider capstoneProvider(&elfBuffer);
        MetadataTargetFactory metadatTargets;
        Storage<std::unique_ptr<IProvider>> scanRanges;
        FromIR2MetadataFactory multiMetadatasBuilder(
            scanRanges,
            &metadatTargets,
            &multiMetadataProvider,
            &fileView,
            &capstoneProvider
        );
        
        auto allMetadata = multiMetadatasBuilder.ProduceAll();
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    return 0;
}