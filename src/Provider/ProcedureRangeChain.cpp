#include <Provider/ProcedureRangeChain.h>
#include <Provider/IAddresses.h>
#include <Provider/IProcedureEntry.h>
#include <PatternScan.h>
#include <Provider/AsmExtractedProcedureEntry.h>
#include <Provider/ProcedureRange.h>

ProcedureRangeProviderChain::ProcedureRangeProviderChain(ICapstoneProvider* cstoneInstanceProvider, IRangeProvider* baseRangeProvider, const std::vector<PatternScanConfig>& nestedProcedurePatterns)
{
    mpRangeProviders.emplace_back(baseRangeProvider);

    for (const auto& procPatternCfg : nestedProcedurePatterns)
    {
        auto addressesProv = (IAddressesProvider*)mProviders.Store(
            std::make_unique<PatternScanAddresses>(mpRangeProviders.back(), procPatternCfg)
        ).get();

        auto procEntryProv = (IProcedureEntryProvider*)mProviders.Store(
            std::make_unique<AsmExtractedProcedureEntryProvider>(cstoneInstanceProvider, addressesProv)
        ).get();

        auto procRangeProv = (IRangeProvider*)mProviders.Store(
            std::make_unique<ProcedureRangeProvider>(cstoneInstanceProvider, procEntryProv)
        ).get();

        mpRangeProviders.push_back(procRangeProv);
    }
}

Range ProcedureRangeProviderChain::GetRange()
{
    return mpRangeProviders.back()->GetRange();
}
