#pragma once

#include <Storage.h>
#include <Provider/IRange.h>
#include <CStone/IProvider.h>
#include <FunctionScanConfig.h>
#include <vector>

class ProcedureRangeProviderChain : public IRangeProvider {
public:
    ProcedureRangeProviderChain(ICapstoneProvider* cstoneInstanceProvider, IRangeProvider* baseRangeProvider, const std::vector<FunctionScanConfig>& nestedProcedurePatterns);

    Range GetRange() override;

    Storage<std::unique_ptr<IProvider>> mProviders;
    std::vector<IRangeProvider*> mpRangeProviders;
};