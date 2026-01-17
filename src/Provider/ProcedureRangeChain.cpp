#include <MHTR/PatternScan.h>
#include <MHTR/Provider/ProcedureRangeChain.h>
#include <MHTR/Provider/IAddresses.h>
#include <MHTR/Provider/IProcedureEntry.h>
#include <MHTR/Provider/AsmExtractedProcedureEntry.h>
#include <MHTR/Provider/ProcedureRange.h>

using namespace MHTR;

ProcedureRangeProviderChain::ProcedureRangeProviderChain(IRangeProvider* baseRangeProvider, const std::vector<FunctionScanConfig>& nestedProcedurePatterns)
{
    mpRangeProviders.emplace_back(baseRangeProvider);

    for (const auto& procPatternCfg : nestedProcedurePatterns)
    {
        auto addressesProv = (IAddressesProvider*)mProviders.Store(
            std::make_unique<PatternScanAddresses>(mpRangeProviders.back(), procPatternCfg.mScanConfig)
        ).get();

        auto procEntryProv = (IProcedureEntryProvider*)mProviders.Store(
            std::make_unique<AsmExtractedProcedureEntryProvider>(procPatternCfg.mCapstoneProvider, addressesProv)
        ).get();

        auto procRangeProv = (IRangeProvider*)mProviders.Store(
            std::make_unique<ProcedureRangeProvider>(procPatternCfg.mCapstoneProvider, procEntryProv, procPatternCfg.mDefSize)
        ).get();

        mpRangeProviders.push_back(procRangeProv);
    }
}

Range ProcedureRangeProviderChain::GetRange()
{
    return mpRangeProviders.back()->GetRange();
}
