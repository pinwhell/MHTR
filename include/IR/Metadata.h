#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <Metadata.h>
#include <variant>

struct PatternScanConfigIR {
    std::string mPattern;
    int64_t mDisp;
};

struct MetadataScanRangeStageFunctionIR {
    uint64_t mDefFnSize;
    PatternScanConfigIR mScanCFG;
};

struct MetadataScanRangeStageIR {
    EMetadataScanRangeStage getType() const;

    std::variant<MetadataScanRangeStageFunctionIR> mStage;
};

struct MetadataScanRangePipelineIR {
    std::vector<MetadataScanRangeStageIR> mStages;
};

struct ScanRangeIR {
    struct Default {};

    EMetadataScanRange getType() const;

    std::variant<Default, MetadataScanRangePipelineIR, std::string> mScanRange;
};

struct MetadataScanRangeIR {
    ScanRangeIR mScanRange;
};

struct MetadataScanComboIR {
    ScanRangeIR mScanRange;
    PatternScanConfigIR mScanCFG;
};

struct PatternValidateLookupIR {
    ScanRangeIR mScanRange;
    std::string mPattern;
    bool mbUnique;
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
};

struct MetadataLookupIR {
    EMetadataLookup getType() const;

    std::variant<PatternValidateLookupIR, PatternSingleResultLookupIR, InsnImmediateLookupIR, FarAddressLookupIR, MetadataResult> mLookup;
};

struct MetadataIR {
    EMetadata getType() const;

    MetadataTargetIR mTarget;
    std::variant<MetadataLookupIR, MetadataScanRangeIR> mMetadata;
};
