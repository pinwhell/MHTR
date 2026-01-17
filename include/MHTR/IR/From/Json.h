#pragma once

#include <MHTR/Provider/IJson.h>
#include <MHTR/IR/IFactory.h>

namespace MHTR {

    class FromJsonMetadataIRParser {
    public:
        MetadataIR Parse(const nlohmann::json& metadata);
    private:
        PatternScanConfigIR ParsePatternScanConfig(const nlohmann::json& scanCfg);
        MetadataScanRangeStageFunctionIR ParseMetadataScanRangeStageFunction(const nlohmann::json& stage);
        MetadataScanRangeStageIR ParseMetadataScanRangeStage(const nlohmann::json& stage);
        MetadataScanRangePipelineIR ParseMetadataScanRangePipeline(const nlohmann::json& pipeline);
        ScanRangeIR ParseScanRange(const nlohmann::json& scanRange);
        MetadataTargetIR ParseMetadataTarget(const nlohmann::json& metadataTarget);
        MetadataScanComboIR ParseMetadataScanCombo(const nlohmann::json& scanCombo);
        PatternValidateLookupIR ParsePatternValidateLookup(const nlohmann::json& metadata);
        PatternSingleResultLookupIR ParsePatternSingleResultLookup(const nlohmann::json& metadata);
        InsnImmediateLookupIR ParseInsnImmediateLookup(const nlohmann::json& metadata);
        FarAddressLookupIR ParseFarAddressLookup(const nlohmann::json& metadata);
        MetadataResult ParseHardcoded(const nlohmann::json& metadata);
        EMetadataLookup TryParseMetadataLookupType(const nlohmann::json& metadata);
        EMetadata TryParseMetadataType(const nlohmann::json& metadata);
        MetadataLookupIR ParseMetadataLookup(const nlohmann::json& lookup);
        MetadataScanRangeIR ParseMetadataScanRange(const nlohmann::json& metadata);
    };

    class FromJsonMultiMetadataIRFactory : public IMultiMetadataIRFactory {
    public:

        FromJsonMultiMetadataIRFactory(IJsonProvider* jsonProvider);

        std::vector<MetadataIR> GetAllMetadatas() override;

        nlohmann::json mJson;
        FromJsonMetadataIRParser mParser;
    };

    template<typename T>
    inline std::optional<T> json_optional_get(const nlohmann::json& j, const std::string& key)
    {
        if (!j.contains(key) || j[key].is_null())
            return std::nullopt;
        return j[key].get<T>();
    }
}