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
            InsnImmediateLookup immLookup(target, &addresses, relDispCalculator, capstoneInstancer, 0);

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

enum class EMetadataLookup {
    NONE,
    PATTERN_VALIDATE,
    PATTERN_SINGLE_RESULT,
    INSN_IMMEDIATE,
    FAR_ADDRESS,
    HARDCODED
};

enum class EMetadataScanRange {
    DEFAULT,
    PIPELINE
};

enum class EMetadataScanRangeStage {
    NONE,
    FUNCTION
};

enum class EHardcodedMetadata {
    PATTERN,
    OFFSET
};

struct PatternScanConfigIR {
    std::string mPattern;
    int64_t mDisp;
};

struct MetadataScanRangeStageFunctionIR {
    uint64_t mDefFnSize;
    PatternScanConfigIR mScanCFG;
};

struct MetadataScanRangeStageIR {
    MetadataScanRangeStageIR()
        : mType(EMetadataScanRangeStage::NONE)
        , mPtr(nullptr)
    {}

    ~MetadataScanRangeStageIR()
    {
        Reset();
    }

    MetadataScanRangeStageIR(MetadataScanRangeStageIR&& other) noexcept
    {
        Reset();

        mType = other.mType;
        mPtr = other.mPtr; other.mPtr = nullptr;
    }

    MetadataScanRangeStageIR(const MetadataScanRangeStageIR&) = delete;
    MetadataScanRangeStageIR& operator=(const MetadataScanRangeStageIR&) = delete;

    EMetadataScanRangeStage mType;

    union {
        MetadataScanRangeStageFunctionIR* mFunction;
        void* mPtr;
    };

private:
    void Reset()
    {
        if (mPtr == nullptr)
            return;

        if (mType == EMetadataScanRangeStage::FUNCTION)
        {
            delete mFunction;
            return;
        }

        mPtr = nullptr;
    }
};

struct MetadataScanRangePipelineIR {
    std::vector<MetadataScanRangeStageIR> mStages;
};

struct MetadataScanRangeIR {

    MetadataScanRangeIR()
    {}

    ~MetadataScanRangeIR() {
       
    }

    MetadataScanRangeIR(MetadataScanRangeIR&& other) noexcept {
        mType = other.mType;
        mPtr = other.mPtr; other.mPtr = nullptr;
    }

    MetadataScanRangeIR(MetadataScanRangeIR&) = delete;
    MetadataScanRangeIR& operator=(MetadataScanRangeIR&) = delete;

    EMetadataScanRange mType;

    union {
        MetadataScanRangePipelineIR* mPipeline;
        void* mPtr;
    };

private:
    void Reset()
    {
        if (mPtr == nullptr)
            return;

        if (mType == EMetadataScanRange::PIPELINE)
        {
            delete mPipeline;
            return;
        }

        mPtr = nullptr;
    }
};

struct MetadataScanComboIR {
    MetadataScanRangeIR mScanRange;
    PatternScanConfigIR mScanCFG;
};

struct PatternValidateLookupIR {
    MetadataScanRangeIR mScanRange;
    std::string mPattern;
};

struct PatternSingleResultLookupIR {
    MetadataScanComboIR mScanCombo;
};

struct InsnImmediateLookupIR {
    MetadataScanComboIR mScanCombo;
    size_t mImmIndex;
};

struct FarAddressLookupIR {
    MetadataScanComboIR mScanCombo;
};

struct MetadataTargetIR {
    std::string mName;
    std::string mNamespace;
};

struct MetadataLookupIR {
    MetadataLookupIR()
        : mType(EMetadataLookup::NONE)
    {
        mPtr = nullptr;
    }

    MetadataLookupIR(MetadataLookupIR&& other)
    {
        Reset();

        mTarget = std::move(other.mTarget);
        mType = other.mType;
        mPtr = other.mPtr; other.mPtr = nullptr;
    }

    ~MetadataLookupIR()
    {
        Reset();
    }

    MetadataLookupIR& operator=(MetadataLookupIR& other)
    {
        Reset();

        mTarget = std::move(other.mTarget);
        mType = other.mType;
        mPtr = other.mPtr; other.mPtr = nullptr;
    }

    MetadataTargetIR mTarget;
    EMetadataLookup mType;

    union {
        PatternValidateLookupIR* mPatternValidate;
        PatternSingleResultLookupIR* mPatternSingleResult;
        InsnImmediateLookupIR* mInsnImmediate;
        FarAddressLookupIR* mFarAddress;
        MetadataResult* mHardcoded;
        void* mPtr;
    };

private:
    void Reset()
    {
        if (mPtr == nullptr)
            return;

        if (mType == EMetadataLookup::HARDCODED)
        {
            delete mHardcoded;
            return;
        }

        if (mType == EMetadataLookup::PATTERN_VALIDATE)
        {
            delete mPatternValidate;
            return;
        }

        if (mType == EMetadataLookup::PATTERN_SINGLE_RESULT)
        {
            delete mPatternSingleResult;
            return;
        }

        if (mType == EMetadataLookup::FAR_ADDRESS)
        {
            delete mFarAddress;
            return;
        }

        if (mType == EMetadataLookup::INSN_IMMEDIATE)
        {
            delete mInsnImmediate;
            return;
        }

        mPtr = nullptr;
    }
};

class UnexpectedLayoutException : public std::runtime_error {
public:
    UnexpectedLayoutException(const std::string& what)
        : std::runtime_error(what)
    {}
};

class JsonMetadataLookupFactory {
public:
    static PatternScanConfigIR ParsePatternScanConfig(const nlohmann::json& scanCfg) {
        return { 
            scanCfg["pattern"].get<std::string>(),
            scanCfg.contains("disp") ? scanCfg["disp"].get<int64_t>() : 0
        };
    }

    static MetadataScanRangeStageFunctionIR ParseMetadataScanRangeStageFunction(const nlohmann::json& stage)
    {
        if (!stage.contains("pattern"))
            throw UnexpectedLayoutException(fmt::format("Pattern Scan Information missing"));

        // At this point, is gurantee 
        // a pattern thing exists

        MetadataScanRangeStageFunctionIR result;

        result.mDefFnSize = stage.contains("defFnSize") ? stage["defFnSize"].get<uint64_t>() : 0;
        result.mScanCFG = stage["pattern"].is_object() ? ParsePatternScanConfig(stage["pattern"]) : ParsePatternScanConfig(stage);

        return result;
    }

    static MetadataScanRangeStageIR ParseMetadataScanRangeStage(const nlohmann::json& stage)
    {
        MetadataScanRangeStageIR result;

        result.mType = EMetadataScanRangeStage::FUNCTION;

        result.mFunction = new MetadataScanRangeStageFunctionIR(
            std::move(
                ParseMetadataScanRangeStageFunction(
                    stage
                )
            )
        );
        
        return result;
    }

    static MetadataScanRangePipelineIR ParseMetadataScanRangePipeline(const nlohmann::json& pipeline)
    {
        if(pipeline.is_array() == false)
            throw UnexpectedLayoutException(fmt::format("Pipeline invalid pipeline type."));

        MetadataScanRangePipelineIR result;

        for (const auto& stage : pipeline)
            result.mStages.emplace_back(std::move(ParseMetadataScanRangeStage(stage)));

        return result;
    }

    static MetadataScanRangeIR ParseMetadataScanRange(const nlohmann::json& scanRange)
    {
        MetadataScanRangeIR result;

        result.mType = EMetadataScanRange::DEFAULT;

        if (scanRange.empty())
            return result;

        if (scanRange.is_array())
        {
            result.mType = EMetadataScanRange::PIPELINE;
            result.mPipeline = new MetadataScanRangePipelineIR(std::move(ParseMetadataScanRangePipeline(scanRange)));

            return result;
        }

        throw UnexpectedLayoutException(fmt::format("Invalid format of scan range"));
    }

    static MetadataTargetIR ParseMetadataTarget(const nlohmann::json& metadataTarget)
    {
        return {
            metadataTarget["name"].get<std::string>(),
            metadataTarget.contains("namespace") ? metadataTarget["name"].get<std::string>() : ""
        };
    }

    static MetadataScanComboIR ParseMetadataScanCombo(const nlohmann::json& scanCombo)
    {
        nlohmann::json scanRange = scanCombo.contains("scanRange") ? scanCombo["scanRange"] : nlohmann::json::parse("{}");

        return {
            std::move(ParseMetadataScanRange(scanRange)),
            std::move(ParsePatternScanConfig(scanCombo.contains("scanCFG") ? scanCombo["scanCFG"] : scanCombo))
        };
    }

    static PatternValidateLookupIR ParsePatternValidateLookup(const nlohmann::json& metadata)
    {
        return {
            std::move(ParseMetadataScanRange(metadata.contains("scanRange") ? metadata["scanRange"] : nlohmann::json::parse("{}"))),
            metadata["pattern"].get<std::string>()
        };
    }

    static PatternSingleResultLookupIR ParsePatternSingleResultLookup(const nlohmann::json& metadata)
    {
        return {
            std::move(ParseMetadataScanCombo(metadata))
        };
    }

    static InsnImmediateLookupIR ParseInsnImmediateLookup(const nlohmann::json& metadata)
    {
        return {
            std::move(ParseMetadataScanCombo(metadata)),
            metadata.contains("immIndex") ? metadata["immIndex"].get<size_t>() : 0
        };
    }

    static FarAddressLookupIR ParseFarAddressLookup(const nlohmann::json& metadata)
    {
        return {
            std::move(ParseMetadataScanCombo(metadata))
        };
    }

    static MetadataResult ParseHardcoded(const nlohmann::json& metadata)
    {
        auto value = metadata["value"];

        if (value.is_number_integer() || value.is_number_unsigned())
            return MetadataResult(value.get<uint64_t>());

        if (value.is_string())
            return MetadataResult(value.get<std::string>());

        throw UnexpectedLayoutException(fmt::format("invalid 'value' format"));
    }

    static EMetadataLookup TryParseMetadataType(const nlohmann::json& metadata)
    {
        if (metadata.contains("type"))
        {
            std::string type = metadata["type"].get<std::string>();

            if (type == "PATTERN_VALIDATE")
                return EMetadataLookup::PATTERN_VALIDATE;

            if (type == "PATTERN_SINGLE_RESULT")
                return EMetadataLookup::PATTERN_SINGLE_RESULT;

            if (type == "INSN_IMM")
                return EMetadataLookup::INSN_IMMEDIATE;

            if (type == "FAR_ADDR")
                return EMetadataLookup::FAR_ADDRESS;

            if (type == "HARDCODED")
                return EMetadataLookup::HARDCODED;

            throw UnexpectedLayoutException(fmt::format("'{}' invalid metadata lookup type", type));
        }

        // At this point, type wasnt defined 
        // explicitly, defaulting to INSN_IMMEDIATE

        return EMetadataLookup::INSN_IMMEDIATE;
    }

    static MetadataLookupIR ParseMetadataLookup(const nlohmann::json& metadata)
    {
        MetadataLookupIR result;

        result.mTarget = std::move(ParseMetadataTarget(metadata));
        result.mType = TryParseMetadataType(metadata);

        try {
            switch (result.mType)
            {
            case EMetadataLookup::PATTERN_VALIDATE:
                result.mPatternValidate = new PatternValidateLookupIR(std::move(ParsePatternValidateLookup(metadata)));
                break;

            case EMetadataLookup::PATTERN_SINGLE_RESULT:
                result.mPatternSingleResult = new PatternSingleResultLookupIR(std::move(ParsePatternSingleResultLookup(metadata)));
                break;

            case EMetadataLookup::INSN_IMMEDIATE:
                result.mInsnImmediate = new InsnImmediateLookupIR(std::move(ParseInsnImmediateLookup(metadata)));
                break;

            case EMetadataLookup::FAR_ADDRESS:
                result.mFarAddress = new FarAddressLookupIR(std::move(ParseFarAddressLookup(metadata)));
                break;

            case EMetadataLookup::HARDCODED:
                result.mHardcoded = new MetadataResult(ParseHardcoded(metadata));
                break;
            }
        }
        catch (const std::exception& e)
        {
            throw UnexpectedLayoutException(fmt::format("'{}':{}", result.mTarget.mName, e.what()));
        }

        return result;
    }

private:    
};

int main(int argc, const char** argv)
{
    //TestDumpMetadata();
    //TestNamespaces();
    //RunMetadataTests();

    auto metadata1 = nlohmann::json::parse(R"(
    {
        "name" : "Foo",
        "namespace" : "Bar", 
        "type" : "INSN_IMM",        
        "immIndex" : 1,             
        "pattern" : "AA BB CC",
        "disp" : -5,                
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
    }
)"); 

    auto metadata1Simple = nlohmann::json::parse(R"(
    {
        "name" : "Foo",                
        "pattern" : "AA BB CC",
        "disp" : "ABCD"
    }
)");

    try {
        auto res1 = JsonMetadataLookupFactory::ParseMetadataLookup(metadata1Simple);
    }
    catch (const std::exception& e)
    {
        std::cout << e.what() << std::endl;
    }

    return 0;
}
