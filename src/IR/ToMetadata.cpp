#include <fmt/core.h>
#include <algorithm>
#include <iterator>
#include <MHTR/IR/ToMetadata.h>
#include <MHTR/Metadata/Lookups.h>
#include <MHTR/Exception/UnexpectedLayout.h>
#include <MHTR/PatternScan.h>
#include <MHTR/FarAddressLookup.h>
#include <MHTR/Provider/ProcedureRangeChain.h>

using namespace MHTR;

FromIRMultiMetadataFactory::FromIRMultiMetadataFactory(Storage<std::unique_ptr<IProvider>>& providersStorage, IMetadataTargetProvider* metadataTargetProvider, IMultiMetadataIRFactory* metadataIRFactory, IRangeProvider* defaultScanRange, IOffsetCalculator* offsetCalculator, ICapstoneProvider* capstoneProvider, IFarAddressResolverProvider* farAddressResolverProvider, INamespaceProvider* nsProvider)
    : mProvidersStorage(providersStorage)
    , mMetadataTargetProvider(metadataTargetProvider)
    , mMetadataIRProvider(metadataIRFactory)
    , mDefaultScanRange(defaultScanRange)
    , mOffsetCalculator(offsetCalculator)
    , mCapstoneProvider(capstoneProvider)
    , mFarAddressResolverProvider(farAddressResolverProvider)
    , mNsProvider(nsProvider)
{}

std::vector<std::unique_ptr<ILookableMetadata>> FromIRMultiMetadataFactory::ProduceAll() {
    std::vector<MetadataIR> allMetadata = mMetadataIRProvider->GetAllMetadatas();
    std::vector<MetadataIR*> allMetadataPtr;

    std::transform(allMetadata.begin(), allMetadata.end(), std::back_inserter(allMetadataPtr), [](MetadataIR& ir) {
        return &ir;
        });

    std::sort(allMetadataPtr.begin(), allMetadataPtr.end(), [](MetadataIR* first, MetadataIR* second /*the functio ask, "is this order right?"*/) {
        return (unsigned)first->getType() > (unsigned)second->getType();
        });

    std::vector<std::unique_ptr<ILookableMetadata>> result;
    std::unordered_set<std::string> uids;

    for (MetadataIR* metadata : allMetadataPtr)
    {
        if (metadata->getType() == EMetadata::METADATA_SCAN_RANGE)
        {
            CreateMetadataScanRangeFromIR(*metadata);
            continue;
        }

        result.emplace_back(CreateMetadataLookupFromIR(*metadata));
    }

    return result;
}

MetadataTarget* FromIRMultiMetadataFactory::MetadataTargetFromIR(const MetadataTargetIR& ir)
{
    INamespace* ns = mNsProvider ? mNsProvider->GetNamespace() : nullptr;

    return mMetadataTargetProvider->GetMetadataTarget(ir.mName, ns);
}

std::unique_ptr<ILookableMetadata> FromIRMultiMetadataFactory::CreateMetadataLookupFromIR(const MetadataIR& ir)
{
    MetadataTarget& target = *MetadataTargetFromIR(ir.mTarget);

    const auto& lookup = std::get<MetadataLookupIR>(ir.mMetadata).mLookup;

    if(std::holds_alternative<PatternValidateLookupIR>(lookup))
        return CreatePatternValidateLookupFromIR(target, std::get<PatternValidateLookupIR>(lookup));

    if (std::holds_alternative<InsnImmediateLookupIR>(lookup))
        return CreateInsnImmLookupFromIR(target, std::get<InsnImmediateLookupIR>(lookup));

    if (std::holds_alternative<FarAddressLookupIR>(lookup))
        return CreateFarAddressLookupFromIR(target, std::get<FarAddressLookupIR>(lookup));

    if (std::holds_alternative<PatternSingleResultLookupIR>(lookup))
        return CreatePatternSingleResultLookupFromIR(target, std::get<PatternSingleResultLookupIR>(lookup));

    if (std::holds_alternative<MetadataResult>(lookup))
        return CreateHardcodedLookupFromIR(target, std::get<MetadataResult>(lookup));

    return 0;
}

std::unique_ptr<ILookableMetadata> FromIRMultiMetadataFactory::CreatePatternValidateLookupFromIR(MetadataTarget& target, const PatternValidateLookupIR& ir)
{
    IRangeProvider* scanRange = CreateScanRangeFromIR(ir.mScanRange);

    return std::make_unique<PatternCheckLookup>(target, scanRange, ir.mPattern, ir.mbUnique);
}

std::unique_ptr<ILookableMetadata> FromIRMultiMetadataFactory::CreateInsnImmLookupFromIR(MetadataTarget& target, const InsnImmediateLookupIR& ir)
{
    auto& scanCombo = ir.mScanCombo;
    auto& scanCFG = scanCombo.mScanCFG;

    IRangeProvider* scanRange = CreateScanRangeFromIR(scanCombo.mScanRange);
    IAddressesProvider* addressesProvider = (IAddressesProvider*)mProvidersStorage.Store(
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

std::unique_ptr<ILookableMetadata> FromIRMultiMetadataFactory::CreateFarAddressLookupFromIR(MetadataTarget& target, const FarAddressLookupIR& ir)
{
    auto& scanCombo = ir.mScanCombo;
    auto& scanCFG = scanCombo.mScanCFG;

    IRangeProvider* scanRange = CreateScanRangeFromIR(scanCombo.mScanRange);
    IAddressesProvider* addressesProvider = (IAddressesProvider*)mProvidersStorage.Store(
        std::make_unique<PatternScanAddresses>(
            scanRange,
            PatternScanConfig(
                scanCFG.mPattern,
                scanCFG.mDisp
            )
        )
    ).get();
    IFarAddressResolver* farAddressResolver = mFarAddressResolverProvider->GetFarAddressResolver(mCapstoneProvider);

    return std::make_unique<FarAddressLookup>(target, addressesProvider, farAddressResolver, mOffsetCalculator);
}

std::unique_ptr<ILookableMetadata> FromIRMultiMetadataFactory::CreatePatternSingleResultLookupFromIR(MetadataTarget& target, const PatternSingleResultLookupIR& ir)
{
    IRangeProvider* scanRange = CreateScanRangeFromIR(ir.mScanCombo.mScanRange);

    return std::make_unique<PatternSingleResultLookup>(target, scanRange, mOffsetCalculator, ir.mScanCombo.mScanCFG.mPattern);
}

std::unique_ptr<ILookableMetadata> FromIRMultiMetadataFactory::CreateHardcodedLookupFromIR(MetadataTarget& target, const MetadataResult& ir)
{
    return std::make_unique<HardcodedLookup>(target, ir);
}

IRangeProvider* FromIRMultiMetadataFactory::CreateMetadataScanRangeFromIR(const MetadataIR& ir)
{
    if (mRangeProviderMap.find(ir.mTarget.mName) != mRangeProviderMap.end())
        throw UnexpectedLayoutException(fmt::format("'{}':Metadata Scan Range duplicated detected."));

    return mRangeProviderMap[ir.mTarget.mName] = CreateScanRangeFromIR(std::get<MetadataScanRangeIR>(ir.mMetadata).mScanRange);
}

IRangeProvider* FromIRMultiMetadataFactory::CreateScanRangeFromIR(const ScanRangeIR& ir)
{
    if (std::holds_alternative<MetadataScanRangePipelineIR>(ir.mScanRange))
        return CreateScanRangePipelineFromIR(std::get<MetadataScanRangePipelineIR>(ir.mScanRange));

    if (std::holds_alternative<std::string>(ir.mScanRange))
    {
        auto& key = std::get<std::string>(ir.mScanRange);

        if (mRangeProviderMap.find(key) == mRangeProviderMap.end())
            throw UnexpectedLayoutException(fmt::format("'{}':Scan Range Reference not found."));

        return mRangeProviderMap[key];
    }

    return mDefaultScanRange;
}

IRangeProvider* FromIRMultiMetadataFactory::CreateScanRangePipelineFromIR(const MetadataScanRangePipelineIR& pipeline)
{
    std::vector<FunctionScanConfig> configs;

    for (const auto& stage : pipeline.mStages)
    {
        if (!std::holds_alternative<MetadataScanRangeStageFunctionIR>(stage.mStage))
            throw std::logic_error(fmt::format("Unimplemented Stage detected"));

        const auto& fnStage = std::get<MetadataScanRangeStageFunctionIR>(stage.mStage);
        const auto& scanCFG = fnStage.mScanCFG;

        configs.emplace_back(std::move(FunctionScanConfig{
            PatternScanConfig(
                scanCFG.mPattern,
                scanCFG.mDisp
            ),             
                size_t(fnStage.mDefFnSize)
            }));
    }

    return (IRangeProvider*)mProvidersStorage.Store(std::make_unique<ProcedureRangeProviderChain>(mCapstoneProvider, mDefaultScanRange, configs)).get();
}
