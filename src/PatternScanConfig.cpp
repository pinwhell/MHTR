#include <PatternScanConfig.h>

PatternScanConfig::PatternScanConfig() : mPattern(""), mResDisp(0) {}

PatternScanConfig::PatternScanConfig(const std::string& pattern, int64_t resultDisplacement) : mPattern(pattern), mResDisp(resultDisplacement) {}

PatternScanConfig::PatternScanConfig(const PatternScanConfig& other) : mPattern(other.mPattern), mResDisp(other.mResDisp) {}

PatternScanConfig::PatternScanConfig(PatternScanConfig&& other) noexcept : mPattern(std::move(other.mPattern)), mResDisp(other.mResDisp) {
    other.mResDisp = 0;
}

PatternScanConfig::~PatternScanConfig() {}

PatternScanConfig& PatternScanConfig::operator=(const PatternScanConfig& other) {
    if (this != &other) {
        mPattern = other.mPattern;
        mResDisp = other.mResDisp;
    }
    return *this;
}

PatternScanConfig& PatternScanConfig::operator=(PatternScanConfig&& other) noexcept {
    if (this != &other) {
        mPattern = std::move(other.mPattern);
        mResDisp = other.mResDisp;
        other.mResDisp = 0;
    }
    return *this;
}