#pragma once

#include <vector>
#include <MHTR/Storage.h>
#include <MHTR/Provider/IRange.h>
#include <MHTR/FunctionScanConfig.h>
#include <CStone/IProvider.h>

class ProcedureRangeProviderChain : public IRangeProvider {
public:
    ProcedureRangeProviderChain(ICapstoneProvider* cstoneInstanceProvider, IRangeProvider* baseRangeProvider, const std::vector<FunctionScanConfig>& nestedProcedurePatterns);

    Range GetRange() override;

    Storage<std::unique_ptr<IProvider>> mProviders;
    std::vector<IRangeProvider*> mpRangeProviders;
};