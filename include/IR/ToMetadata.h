#pragma once

#include <Storage.h>
#include <Provider/IMetadataTarget.h>
#include <IR/IProvider.h>
#include <Provider/IRelativeDisp.h>
#include <CStone/IProvider.h>
#include <Provider/IFarAddress.h> 
#include <vector>
#include <unordered_map>
#include <Provider/IRange.h>
#include <Synther/INamespace.h>

class FromIR2MetadataFactory {
public:
    FromIR2MetadataFactory(
        Storage<std::unique_ptr<IProvider>>& providersStorage,
        IMetadataTargetProvider* metadataTargetProvider,
        IMultiMetadataIRProvider* metadataIRProvider,
        IRangeProvider* defaultScanRange,
        IRelativeDispProvider* relDispCalculator,
        ICapstoneProvider* capstoneProvider,
        IFarAddressResolverProvider* farAddressResolverProvider,
        INamespace* ns = nullptr
    );

    std::vector<std::unique_ptr<ILookableMetadata>> ProduceAll();

    Storage<std::unique_ptr<IProvider>>& mProvidersStorage;
    IMetadataTargetProvider* mMetadataTargetProvider;
    IMultiMetadataIRProvider* mMetadataIRProvider;
    IRangeProvider* mDefaultScanRange;
    IRelativeDispProvider* mRelDispCalculator;
    ICapstoneProvider* mCapstoneProvider;
    IFarAddressResolverProvider* mFarAddressResolverProvider;
    INamespace* mNs;

    // Internal
    std::unordered_map<std::string, IRangeProvider*> mRangeProviderMap;

private:
    MetadataTarget* MetadataTargetFromIR(const MetadataTargetIR& ir);

    std::unique_ptr<ILookableMetadata> CreateMetadataLookupFromIR(const MetadataIR& ir);
    std::unique_ptr<ILookableMetadata> CreatePatternValidateLookupFromIR(MetadataTarget& target, const PatternValidateLookupIR& ir);
    std::unique_ptr<ILookableMetadata> CreateInsnImmLookupFromIR(MetadataTarget& target, const InsnImmediateLookupIR& ir);
    std::unique_ptr<ILookableMetadata> CreateFarAddressLookupFromIR(MetadataTarget& target, const FarAddressLookupIR& ir);
    std::unique_ptr<ILookableMetadata> CreatePatternSingleResultLookupFromIR(MetadataTarget& target, const PatternSingleResultLookupIR& ir);
    std::unique_ptr<ILookableMetadata> CreateHardcodedLookupFromIR(MetadataTarget& target, const MetadataResult& ir);

    IRangeProvider* CreateMetadataScanRangeFromIR(const MetadataIR& ir);
    IRangeProvider* CreateScanRangeFromIR(const ScanRangeIR& ir);
    IRangeProvider* CreateScanRangePipelineFromIR(const MetadataScanRangePipelineIR& pipeline);
};