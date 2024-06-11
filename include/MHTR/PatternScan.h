#pragma once

#include <string>
#include <stdexcept>
#include <MHTR/Provider/IAddresses.h>
#include <MHTR/Provider/IRange.h>
#include <MHTR/PatternScanConfig.h>
#include <TBS.hpp>

class PatternScanException : public std::runtime_error {
public:
    PatternScanException(const std::string& what);
};

void PatternScanOrExcept(IRangeProvider* scanRangeProvider, const std::string& pattern, TBS::Pattern::Results& results, bool bUniqueLookup = false);
void PatternScanOrExceptWithName(const std::string& name, IRangeProvider* scanRangeProvider, const std::string& pattern, TBS::Pattern::Results& results, bool bUniqueLookup = false);

class PatternScanAddresses : public IAddressesProvider {
public:
    PatternScanAddresses(IRangeProvider* scanRangeProvider, const std::string& pattern, int64_t resDisp = 0);
    PatternScanAddresses(IRangeProvider* scanRangeProvider, const PatternScanConfig& scanCfg);

    std::vector<uint64_t> GetAllAddresses() override;

    IRangeProvider* mScanRangeProvider;
    PatternScanConfig mScanCFG;
};
