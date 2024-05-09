#include <PatternScan.h>
#include <fmt/core.h>

PatternScanException::PatternScanException(const std::string& what)
	: std::runtime_error(what)
{}

void PatternScanOrExcept(const BufferView& scanRange, const std::string& pattern, TBS::Pattern::Results& results, bool bUniqueLookup)
{
	if (!TBS::Light::Scan(scanRange.start(), scanRange.end(), results, pattern.c_str()))
		throw PatternScanException(fmt::format("'{}' not found.", pattern));

	if (bUniqueLookup && results.size() != 1)
		throw PatternScanException(fmt::format("'{}' not unique with {} results.", pattern, results.size()));
}

void PatternScanOrExceptWithName(const std::string& name, const BufferView& scanRange, const std::string& pattern, TBS::Pattern::Results& results, bool bUniqueLookup)
{
	try {
		PatternScanOrExcept(scanRange, pattern, results, bUniqueLookup);
	}
	catch (const PatternScanException& e) {
		throw PatternScanException(fmt::format("'{}':{}", name, e.what()));
	}
}

PatternScanAddresses::PatternScanAddresses(IRangeProvider* scanRangeProvider, const std::string& pattern, int64_t resDisp)
    : mScanRangeProvider(scanRangeProvider)
    , mPattern(pattern)
    , mDisp(resDisp)
{}

std::vector<uint64_t> PatternScanAddresses::GetAllAddresses()
{
    std::vector<uint64_t> results;
	BufferView scanRange = mScanRangeProvider->GetRange();

    PatternScanOrExcept(scanRange, mPattern, results, false);

    for (auto& result : results)
        result += mDisp;

    return results;
}
