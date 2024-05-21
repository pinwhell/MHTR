#include <PatternScan.h>
#include <fmt/core.h>

PatternScanException::PatternScanException(const std::string& what)
	: std::runtime_error(what)
{}

void PatternScanOrExcept(IRangeProvider* scanRangeProvider, const std::string& pattern, TBS::Pattern::Results& results, bool bUniqueLookup)
{
	BufferView bv = scanRangeProvider->GetRange();

	if (!TBS::Light::Scan(bv.start(), bv.end(), results, pattern.c_str()))
		throw PatternScanException(fmt::format("'{}' not found.", pattern));

	if (bUniqueLookup && results.size() != 1)
		throw PatternScanException(fmt::format("'{}' not unique with {} results.", pattern, results.size()));
}

void PatternScanOrExceptWithName(const std::string& name, IRangeProvider* scanRangeProvider, const std::string& pattern, TBS::Pattern::Results& results, bool bUniqueLookup)
{
	try {
		PatternScanOrExcept(scanRangeProvider, pattern, results, bUniqueLookup);
	}
	catch (const PatternScanException& e) {
		throw PatternScanException(fmt::format("'{}':{}", name, e.what()));
	}
}

PatternScanAddresses::PatternScanAddresses(IRangeProvider* scanRangeProvider, const std::string& pattern, int64_t resDisp)
    : PatternScanAddresses(scanRangeProvider, PatternScanConfig(pattern, resDisp))
{}

PatternScanAddresses::PatternScanAddresses(IRangeProvider* scanRangeProvider, const PatternScanConfig& scanCfg)
	: mScanRangeProvider(scanRangeProvider)
	, mScanCFG(scanCfg)
{}

std::vector<uint64_t> PatternScanAddresses::GetAllAddresses()
{
    std::vector<uint64_t> results;

    PatternScanOrExcept(mScanRangeProvider, mScanCFG.mPattern, results, false);

    for (auto& result : results)
        result += mScanCFG.mResDisp;

    return results;
}
