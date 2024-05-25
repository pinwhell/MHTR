#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <Metadata.h>

struct PatternScanConfigIR {
    std::string mPattern;
    int64_t mDisp;
};

struct MetadataScanRangeStageFunctionIR {
    uint64_t mDefFnSize;
    PatternScanConfigIR mScanCFG;
};

struct MetadataScanRangeStageIR {
    MetadataScanRangeStageIR();
    MetadataScanRangeStageIR(MetadataScanRangeStageIR&& other) noexcept;
    MetadataScanRangeStageIR(const MetadataScanRangeStageIR&) = delete;
    MetadataScanRangeStageIR& operator=(const MetadataScanRangeStageIR&) = delete;
    ~MetadataScanRangeStageIR();

    EMetadataScanRangeStage mType;

    union {
        MetadataScanRangeStageFunctionIR* mFunction;
        void* mPtr;
    };

private:
    void Reset();
};

struct MetadataScanRangePipelineIR {
    std::vector<MetadataScanRangeStageIR> mStages;
};

struct ScanRangeIR {

    ScanRangeIR();
    ScanRangeIR(ScanRangeIR&& other) noexcept;
    ScanRangeIR(ScanRangeIR&) = delete;
    ScanRangeIR& operator=(ScanRangeIR&) = delete;
    ~ScanRangeIR();

    EMetadataScanRange mType;

    union {
        MetadataScanRangePipelineIR* mPipeline;
        std::string* mRef;
        void* mPtr;
    };

private:
    void Reset();
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
    MetadataLookupIR();
    MetadataLookupIR(MetadataLookupIR&& other);
    ~MetadataLookupIR();
    MetadataLookupIR(MetadataLookupIR&) = delete;
    MetadataLookupIR& operator=(MetadataLookupIR&) = delete;

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
    void Reset();
};

struct MetadataIR {

    MetadataIR();
    MetadataIR(MetadataIR&& other) noexcept;
    MetadataIR(MetadataIR&) = delete;
    MetadataIR& operator=(MetadataIR&) = delete;

    MetadataTargetIR mTarget;
    EMetadata mType;

    union {
        MetadataLookupIR* mLookup;
        MetadataScanRangeIR* mScanRange;
        void* mPtr;
    };

private:
    void Reset();
};
