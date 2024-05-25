#pragma once

#include <IR/IProvider.h>
#include <nlohmann/json.hpp>

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

class FromJsonMultiMetadataIRProvider : public IMultiMetadataIRProvider {
public:

    FromJsonMultiMetadataIRProvider(const std::string& jsonSrc);

    std::vector<MetadataIR> GetAllMetadatas() override;

    FromJsonMetadataIRParser mParser;
    std::string mJsonSrc;
};