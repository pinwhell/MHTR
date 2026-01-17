#include <fmt/core.h>
#include <MHTR/IR/From/Json.h>
#include <MHTR/Exception/UnexpectedLayout.h>

using namespace MHTR;



std::optional<ECapstoneArchMode> json_optional_ECapstoneArchMode_or_throw(const nlohmann::json& stage, const std::string& name)
{
    auto archModeStr = json_optional_get<std::string>(stage, name);
    if (!archModeStr)
        return std::nullopt;

    auto archMode = ECapstoneArchModeFromString(*archModeStr);
    if (archMode == ECapstoneArchMode::UNDEFINED)
        throw UnexpectedLayoutException(
            fmt::format("invalid binaryArchMode '{}'", *archModeStr)
        );

    return archMode;
}

EMetadataScanRangeStage MetadataScanRangeStageIR::getType() const
{
    return (EMetadataScanRangeStage) mStage.index();
}

EMetadataLookup MetadataLookupIR::getType() const
{
    return (EMetadataLookup)mLookup.index();
}

EMetadata MetadataIR::getType() const
{
    return (EMetadata)mMetadata.index();
}

FromJsonMultiMetadataIRFactory::FromJsonMultiMetadataIRFactory(IJsonProvider* jsonProvider)
    : mJson(*jsonProvider->GetJson())
{}

std::vector<MetadataIR> FromJsonMultiMetadataIRFactory::GetAllMetadatas() {
    std::vector<MetadataIR> result;

    for (const auto& metadata : mJson)
        result.emplace_back(std::move(mParser.Parse(metadata)));

    return result;
}

MetadataIR FromJsonMetadataIRParser::Parse(const nlohmann::json& metadata)
{
    MetadataIR result;

    result.mTarget = std::move(ParseMetadataTarget(metadata));

    try {
        switch (TryParseMetadataType(metadata))
        {
        case EMetadata::METADATA_LOOKUP:
            result.mMetadata = MetadataLookupIR(std::move(ParseMetadataLookup(metadata)));
            break;

        case EMetadata::METADATA_SCAN_RANGE:
            result.mMetadata = MetadataScanRangeIR(std::move(ParseMetadataScanRange(metadata)));
            break;
        }
    }
    catch (const std::exception& e)
    {
        throw UnexpectedLayoutException(fmt::format("'{}':{}", result.mTarget.mName, e.what()));
    }

    return result;
}

PatternScanConfigIR FromJsonMetadataIRParser::ParsePatternScanConfig(const nlohmann::json& scanCfg) {
    return {
        scanCfg["pattern"].get<std::string>(),
        scanCfg.contains("disp") ? scanCfg["disp"].get<int64_t>() : 0
    };
}

MetadataScanRangeStageFunctionIR FromJsonMetadataIRParser::ParseMetadataScanRangeStageFunction(const nlohmann::json& stage)
{
    if (!stage.contains("pattern"))
        throw UnexpectedLayoutException(fmt::format("Pattern Scan Information missing"));

    // At this point, is gurantee 
    // a pattern thing exists

    MetadataScanRangeStageFunctionIR result;

    result.mDefFnSize = stage.contains("defFnSize") ? stage["defFnSize"].get<uint64_t>() : 0;
    result.mScanCFG = stage["pattern"].is_object() ? ParsePatternScanConfig(stage["pattern"]) : ParsePatternScanConfig(stage);
    result.mBinaryArchMode = json_optional_ECapstoneArchMode_or_throw(stage, "binaryArchMode");

    return result;
}

MetadataScanRangeStageIR FromJsonMetadataIRParser::ParseMetadataScanRangeStage(const nlohmann::json& stage)
{
    MetadataScanRangeStageIR result;

    result.mStage = MetadataScanRangeStageFunctionIR(
        std::move(
            ParseMetadataScanRangeStageFunction(
                stage
            )
        )
    );

    return result;
}

MetadataScanRangePipelineIR FromJsonMetadataIRParser::ParseMetadataScanRangePipeline(const nlohmann::json& pipeline)
{
    if (pipeline.is_array() == false)
        throw UnexpectedLayoutException(fmt::format("Pipeline invalid pipeline type."));

    MetadataScanRangePipelineIR result;

    for (const auto& stage : pipeline)
        result.mStages.emplace_back(std::move(ParseMetadataScanRangeStage(stage)));

    return result;
}

EMetadataScanRange ScanRangeIR::getType() const
{
    return (EMetadataScanRange) mScanRange.index();
}

ScanRangeIR FromJsonMetadataIRParser::ParseScanRange(const nlohmann::json& scanRange)
{
    ScanRangeIR result;

    result.mScanRange = ScanRangeIR::Default{};

    if (scanRange.empty())
        return result;

    if (scanRange.is_array())
    {
        result.mScanRange = MetadataScanRangePipelineIR(std::move(ParseMetadataScanRangePipeline(scanRange)));
        return result;
    }

    if (scanRange.is_string())
    {
        result.mScanRange = std::string(scanRange.get<std::string>());
        return result;
    }

    throw UnexpectedLayoutException(fmt::format("Invalid format of scan range"));
}

MetadataTargetIR FromJsonMetadataIRParser::ParseMetadataTarget(const nlohmann::json& metadataTarget)
{
    return {
        metadataTarget["name"].get<std::string>()
    };
}

MetadataScanComboIR FromJsonMetadataIRParser::ParseMetadataScanCombo(const nlohmann::json& scanCombo)
{
    nlohmann::json scanRange = scanCombo.contains("scanRange") ? scanCombo["scanRange"] : nlohmann::json::parse("{}");

    return {
        std::move(ParseScanRange(scanRange)),
        std::move(ParsePatternScanConfig(scanCombo.contains("scanCFG") ? scanCombo["scanCFG"] : scanCombo))
    };
}

PatternValidateLookupIR FromJsonMetadataIRParser::ParsePatternValidateLookup(const nlohmann::json& metadata)
{
    return {
        std::move(ParseScanRange(metadata.contains("scanRange") ? metadata["scanRange"] : nlohmann::json::parse("{}"))),
        metadata["pattern"].get<std::string>(),
        metadata.contains("unique") ? metadata["unique"].get<bool>() : false
    };
}

PatternSingleResultLookupIR FromJsonMetadataIRParser::ParsePatternSingleResultLookup(const nlohmann::json& metadata)
{
    return {
        std::move(ParseMetadataScanCombo(metadata))
    };
}

InsnImmediateLookupIR FromJsonMetadataIRParser::ParseInsnImmediateLookup(const nlohmann::json& metadata)
{
    return {
        std::move(ParseMetadataScanCombo(metadata)),
        metadata.contains("immIndex") ? metadata["immIndex"].get<size_t>() : 0,
        json_optional_ECapstoneArchMode_or_throw(metadata, "binaryArchMode")
    };
}

FarAddressLookupIR FromJsonMetadataIRParser::ParseFarAddressLookup(const nlohmann::json& metadata)
{
    return {
        std::move(ParseMetadataScanCombo(metadata)),
        json_optional_ECapstoneArchMode_or_throw(metadata, "binaryArchMode")
    };
}

MetadataResult FromJsonMetadataIRParser::ParseHardcoded(const nlohmann::json& metadata)
{
    auto value = metadata["value"];

    if (value.is_number_integer() || value.is_number_unsigned())
        return MetadataResult(value.get<uint64_t>());

    if (value.is_string())
        return MetadataResult(value.get<std::string>());

    throw UnexpectedLayoutException(fmt::format("invalid 'value' format"));
}

MetadataScanRangeIR FromJsonMetadataIRParser::ParseMetadataScanRange(const nlohmann::json& metadata)
{
    return {
        std::move(ParseScanRange(metadata.contains("scanRange") ? metadata["scanRange"] : nlohmann::json::parse("{}")))
    };
}

EMetadataLookup FromJsonMetadataIRParser::TryParseMetadataLookupType(const nlohmann::json& metadata)
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

EMetadata FromJsonMetadataIRParser::TryParseMetadataType(const nlohmann::json& metadata)
{
    bool bTypeExist = metadata.contains("type");
    bool bNameExist = metadata.contains("name");
    bool bScanRangeExist = metadata.contains("scanRange");
    int scanRangeArgsCount = bTypeExist + bNameExist + bScanRangeExist;
    bool bIsScanRangeMetadata = scanRangeArgsCount == metadata.size() && bScanRangeExist;

    if (bIsScanRangeMetadata)
        return EMetadata::METADATA_SCAN_RANGE;

    return EMetadata::METADATA_LOOKUP;
}

MetadataLookupIR FromJsonMetadataIRParser::ParseMetadataLookup(const nlohmann::json& lookup)
{
    MetadataLookupIR result;

    switch (TryParseMetadataLookupType(lookup))
    {
    case EMetadataLookup::PATTERN_VALIDATE:
        result.mLookup = PatternValidateLookupIR(std::move(ParsePatternValidateLookup(lookup)));
        break;

    case EMetadataLookup::PATTERN_SINGLE_RESULT:
        result.mLookup = PatternSingleResultLookupIR(std::move(ParsePatternSingleResultLookup(lookup)));
        break;

    case EMetadataLookup::INSN_IMMEDIATE:
        result.mLookup = InsnImmediateLookupIR(std::move(ParseInsnImmediateLookup(lookup)));
        break;

    case EMetadataLookup::FAR_ADDRESS:
        result.mLookup = FarAddressLookupIR(std::move(ParseFarAddressLookup(lookup)));
        break;

    case EMetadataLookup::HARDCODED:
        result.mLookup = MetadataResult(ParseHardcoded(lookup));
        break;
    }

    return result;
}