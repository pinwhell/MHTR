#pragma once

#include <unordered_map>
#include <CStone/IProvider.h>
#include <MHTR/Storage.h>
#include <MHTR/Provider/IMetadataTarget.h>
#include <MHTR/Provider/IRange.h>
#include <MHTR/Provider/IFarAddress.h> 
#include <MHTR/Provider/INamespace.h>
#include <MHTR/Factory/IMultiMetadata.h>
#include <MHTR/IR/IFactory.h>
#include <MHTR/IOffsetCalculator.h>
#include <MHTR/Provider/CapstoneFactoryAndProvider.h>

namespace MHTR {
    class FromIRMultiMetadataFactory : public IMultiMetadataFactory {
    public:
        FromIRMultiMetadataFactory(
            Storage<std::unique_ptr<IProvider>>& providersStorage,
            IMetadataTargetProvider* metadataTargetProvider,
            IMultiMetadataIRFactory* metadataIRFactory,
            IRangeProvider* defaultScanRange,
            IOffsetCalculator* offsetCalculator,
            ICapstoneProvider* defCapstoneProvider,
            IFarAddressResolverProvider* farAddressResolverProvider,
            INamespaceProvider* nsProvider = nullptr
        );

        std::vector<std::unique_ptr<ILookableMetadata>> ProduceAll() override;

        Storage<std::unique_ptr<IProvider>>& mProvidersStorage;
        IMetadataTargetProvider* mMetadataTargetProvider;
        IMultiMetadataIRFactory* mMetadataIRProvider;
        IRangeProvider* mDefaultScanRange;
        IOffsetCalculator* mOffsetCalculator;
        ICapstoneProvider* mDefaultCapstoneProvider;
        IFarAddressResolverProvider* mFarAddressResolverProvider;
        INamespaceProvider* mNsProvider;

        // Internal
        std::unordered_map<std::string, IRangeProvider*> mRangeProviderMap;
        std::unordered_map<ECapstoneArchMode, CapstoneFactoryAndProvider*> mCapstoneFactoriesAndProvidersMap;

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

        ICapstoneProvider* GetCapstoneProvider(std::optional<ECapstoneArchMode> mode = std::nullopt);
    };
}