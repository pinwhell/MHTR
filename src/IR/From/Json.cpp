#include <IR/From/Json.h>
#include <fmt/core.h>
#include <Exception/UnexpectedLayout.h>

MetadataScanRangeStageIR::MetadataScanRangeStageIR()
    : mType(EMetadataScanRangeStage::NONE)
    , mPtr(nullptr)
{}

MetadataScanRangeStageIR::~MetadataScanRangeStageIR()
{
    Reset();
}

void MetadataScanRangeStageIR::Reset()
{
    if (mPtr == nullptr)
        return;

    if (mType == EMetadataScanRangeStage::FUNCTION)
        delete mFunction;

    mPtr = nullptr;
}

MetadataScanRangeStageIR::MetadataScanRangeStageIR(MetadataScanRangeStageIR&& other) noexcept
{
    Reset();

    mType = other.mType;
    mPtr = other.mPtr; other.mPtr = nullptr;
}

ScanRangeIR::ScanRangeIR()
{}

ScanRangeIR::~ScanRangeIR() {

}

void ScanRangeIR::Reset()
{
    if (mPtr == nullptr)
        return;

    if (mType == EMetadataScanRange::PIPELINE)
        delete mPipeline;

    else if (mType == EMetadataScanRange::REFERENCE)
        delete mRef;

    mPtr = nullptr;
}

ScanRangeIR::ScanRangeIR(ScanRangeIR&& other) noexcept {
    mType = other.mType;
    mPtr = other.mPtr; other.mPtr = nullptr;
}

MetadataLookupIR::MetadataLookupIR()
    : mType(EMetadataLookup::NONE)
{
    mPtr = nullptr;
}

MetadataLookupIR::MetadataLookupIR(MetadataLookupIR&& other)
{
    Reset();

    mType = other.mType;
    mPtr = other.mPtr; other.mPtr = nullptr;
}

MetadataLookupIR::~MetadataLookupIR()
{
    Reset();
}

void MetadataLookupIR::Reset()
{
    if (mPtr == nullptr)
        return;

    if (mType == EMetadataLookup::HARDCODED)
        delete mHardcoded;

    else if (mType == EMetadataLookup::PATTERN_VALIDATE)
        delete mPatternValidate;

    else if (mType == EMetadataLookup::PATTERN_SINGLE_RESULT)
        delete mPatternSingleResult;

    else if (mType == EMetadataLookup::FAR_ADDRESS)
        delete mFarAddress;

    else if (mType == EMetadataLookup::INSN_IMMEDIATE)
        delete mInsnImmediate;

    mPtr = nullptr;
}

MetadataIR::MetadataIR()
    : mType(EMetadata::NONE)
    , mPtr(nullptr)
{}

MetadataIR::MetadataIR(MetadataIR&& other) noexcept
{
    Reset();

    mTarget = std::move(other.mTarget);
    mType = other.mType;
    mPtr = other.mPtr; other.mPtr = nullptr;
}

void MetadataIR::Reset()
{
    if (!mPtr)
        return;

    if (mType == EMetadata::METADATA_LOOKUP)
        delete mLookup;

    else if (mType == EMetadata::METADATA_SCAN_RANGE)
        delete mScanRange;

    mPtr = nullptr;
}

FromJsonMultiMetadataIRProvider::FromJsonMultiMetadataIRProvider(const std::string& jsonSrc)
    : mJsonSrc(jsonSrc)
{}

std::vector<MetadataIR> FromJsonMultiMetadataIRProvider::GetAllMetadatas() {
    auto multiMetadataJsonObj = nlohmann::json::parse(mJsonSrc);
    std::vector<MetadataIR> result;

    for (const auto& metadata : multiMetadataJsonObj)
        result.emplace_back(std::move(mParser.Parse(metadata)));

    return result;
}

MetadataIR FromJsonMetadataIRParser::Parse(const nlohmann::json& metadata)
{
    MetadataIR result;

    result.mTarget = std::move(ParseMetadataTarget(metadata));
    result.mType = TryParseMetadataType(metadata);

    try {
        switch (result.mType)
        {
        case EMetadata::METADATA_LOOKUP:
            result.mLookup = new MetadataLookupIR(std::move(ParseMetadataLookup(metadata)));
            break;

        case EMetadata::METADATA_SCAN_RANGE:
            result.mScanRange = new MetadataScanRangeIR(std::move(ParseMetadataScanRange(metadata)));
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

    return result;
}

MetadataScanRangeStageIR FromJsonMetadataIRParser::ParseMetadataScanRangeStage(const nlohmann::json& stage)
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

MetadataScanRangePipelineIR FromJsonMetadataIRParser::ParseMetadataScanRangePipeline(const nlohmann::json& pipeline)
{
    if (pipeline.is_array() == false)
        throw UnexpectedLayoutException(fmt::format("Pipeline invalid pipeline type."));

    MetadataScanRangePipelineIR result;

    for (const auto& stage : pipeline)
        result.mStages.emplace_back(std::move(ParseMetadataScanRangeStage(stage)));

    return result;
}

ScanRangeIR FromJsonMetadataIRParser::ParseScanRange(const nlohmann::json& scanRange)
{
    ScanRangeIR result;

    result.mType = EMetadataScanRange::DEFAULT;

    if (scanRange.empty())
        return result;

    if (scanRange.is_array())
    {
        result.mType = EMetadataScanRange::PIPELINE;
        result.mPipeline = new MetadataScanRangePipelineIR(std::move(ParseMetadataScanRangePipeline(scanRange)));

        return result;
    }

    if (scanRange.is_string())
    {
        result.mType = EMetadataScanRange::REFERENCE;
        result.mRef = new std::string(scanRange.get<std::string>());

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
        metadata.contains("immIndex") ? metadata["immIndex"].get<size_t>() : 0
    };
}

FarAddressLookupIR FromJsonMetadataIRParser::ParseFarAddressLookup(const nlohmann::json& metadata)
{
    return {
        std::move(ParseMetadataScanCombo(metadata))
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

    result.mType = TryParseMetadataLookupType(lookup);

    switch (result.mType)
    {
    case EMetadataLookup::PATTERN_VALIDATE:
        result.mPatternValidate = new PatternValidateLookupIR(std::move(ParsePatternValidateLookup(lookup)));
        break;

    case EMetadataLookup::PATTERN_SINGLE_RESULT:
        result.mPatternSingleResult = new PatternSingleResultLookupIR(std::move(ParsePatternSingleResultLookup(lookup)));
        break;

    case EMetadataLookup::INSN_IMMEDIATE:
        result.mInsnImmediate = new InsnImmediateLookupIR(std::move(ParseInsnImmediateLookup(lookup)));
        break;

    case EMetadataLookup::FAR_ADDRESS:
        result.mFarAddress = new FarAddressLookupIR(std::move(ParseFarAddressLookup(lookup)));
        break;

    case EMetadataLookup::HARDCODED:
        result.mHardcoded = new MetadataResult(ParseHardcoded(lookup));
        break;
    }

    return result;
}