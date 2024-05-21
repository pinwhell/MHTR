#pragma once

#include <string>
#include <cstdint>

struct PatternScanConfig {
public:
    PatternScanConfig();
    PatternScanConfig(const std::string& pattern, int64_t resultDisplacement);
    PatternScanConfig(const PatternScanConfig& other);
    PatternScanConfig(PatternScanConfig&& other) noexcept;
    ~PatternScanConfig();

    PatternScanConfig& operator=(const PatternScanConfig& other);
    PatternScanConfig& operator=(PatternScanConfig&& other) noexcept;

    std::string mPattern;
    int64_t mResDisp;
};