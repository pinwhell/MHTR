#include <IR/ToMetadata.h>
#include <Exception/UnexpectedLayout.h>
#include <PatternScan.h>
#include <FarAddressLookup.h>
#include <fmt/core.h>
#include <Provider/ProcedureRangeChain.h>

FromIR2MetadataFactory::FromIR2MetadataFactory(Storage<std::unique_ptr<IProvider>>& providersStorage, IMetadataTargetProvider* metadataTargetProvider, IMultiMetadataIRProvider* metadataIRProvider, IRangeProvider* defaultScanRange, IRelativeDispProvider* relDispCalculator, ICapstoneProvider* capstoneProvider, IFarAddressResolverProvider* farAddressResolverProvider, INamespace* ns)
    : mProvidersStorage(providersStorage)
    , mMetadataTargetProvider(metadataTargetProvider)
    , mMetadataIRProvider(metadataIRProvider)
    , mDefaultScanRange(defaultScanRange)
    , mRelDispCalculator(relDispCalculator)
    , mCapstoneProvider(capstoneProvider)
    , mFarAddressResolverProvider(farAddressResolverProvider)
    , mNs(ns)
{}

std::vector<std::unique_ptr<ILookableMetadata>> FromIR2MetadataFactory::ProduceAll() {
    std::vector<MetadataIR> allMetadata = mMetadataIRProvider->GetAllMetadatas();

    for (MetadataIR& metadata : allMetadata)
    {
        if (metadata.getType() != EMetadata::METADATA_SCAN_RANGE)
            continue;

        CreateMetadataScanRangeFromIR(metadata);
    }

    std::vector<std::unique_ptr<ILookableMetadata>> result;

    for (MetadataIR& metadata : allMetadata)
    {
        if (metadata.getType() != EMetadata::METADATA_LOOKUP)
            continue;

        result.emplace_back(std::move(CreateMetadataLookupFromIR(metadata)));
    }

    return result;
}

MetadataTarget* FromIR2MetadataFactory::MetadataTargetFromIR(const MetadataTargetIR& ir)
{
    return mMetadataTargetProvider->GetMetadataTarget(ir.mName, mNs);
}

std::unique_ptr<ILookableMetadata> FromIR2MetadataFactory::CreateMetadataLookupFromIR(const MetadataIR& ir)
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

std::unique_ptr<ILookableMetadata> FromIR2MetadataFactory::CreatePatternValidateLookupFromIR(MetadataTarget& target, const PatternValidateLookupIR& ir)
{
    IRangeProvider* scanRange = CreateScanRangeFromIR(ir.mScanRange);

    return std::make_unique<PatternCheckLookup>(target, scanRange, ir.mPattern, ir.mbUnique);
}

std::unique_ptr<ILookableMetadata> FromIR2MetadataFactory::CreateInsnImmLookupFromIR(MetadataTarget& target, const InsnImmediateLookupIR& ir)
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

std::unique_ptr<ILookableMetadata> FromIR2MetadataFactory::CreateFarAddressLookupFromIR(MetadataTarget& target, const FarAddressLookupIR& ir)
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

    return std::make_unique<FarAddressLookup>(target, addressesProvider, farAddressResolver, mRelDispCalculator);
}

std::unique_ptr<ILookableMetadata> FromIR2MetadataFactory::CreatePatternSingleResultLookupFromIR(MetadataTarget& target, const PatternSingleResultLookupIR& ir)
{
    IRangeProvider* scanRange = CreateScanRangeFromIR(ir.mScanCombo.mScanRange);

    return std::make_unique<PatternSingleResultLookup>(target, scanRange, ir.mScanCombo.mScanCFG.mPattern);
}

std::unique_ptr<ILookableMetadata> FromIR2MetadataFactory::CreateHardcodedLookupFromIR(MetadataTarget& target, const MetadataResult& ir)
{
    return std::make_unique<HardcodedLookup>(target, ir);
}

IRangeProvider* FromIR2MetadataFactory::CreateMetadataScanRangeFromIR(const MetadataIR& ir)
{
    if (mRangeProviderMap.find(ir.mTarget.mName) != mRangeProviderMap.end())
        throw UnexpectedLayoutException(fmt::format("'{}':Metadata Scan Range duplicated detected."));

    return mRangeProviderMap[ir.mTarget.mName] = CreateScanRangeFromIR(std::get<MetadataScanRangeIR>(ir.mMetadata).mScanRange);
}

IRangeProvider* FromIR2MetadataFactory::CreateScanRangeFromIR(const ScanRangeIR& ir)
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

IRangeProvider* FromIR2MetadataFactory::CreateScanRangePipelineFromIR(const MetadataScanRangePipelineIR& pipeline)
{
    std::vector<PatternScanConfig> configs;

    for (const auto& stage : pipeline.mStages)
    {
        if (!std::holds_alternative<MetadataScanRangeStageFunctionIR>(stage.mStage))
            throw std::logic_error(fmt::format("Unimplemented Stage detected"));

        const auto& scanCFG = std::get<MetadataScanRangeStageFunctionIR>(stage.mStage).mScanCFG;

        configs.emplace_back(std::move(PatternScanConfig(
            scanCFG.mPattern,
            scanCFG.mDisp
        )));
    }

    return (IRangeProvider*)mProvidersStorage.Store(std::make_unique<ProcedureRangeProviderChain>(mCapstoneProvider, mDefaultScanRange, configs)).get();
}
