#pragma once

#include <Storage.h>
#include <Provider/IRange.h>
#include <CStone/IProvider.h>
#include <PatternScanConfig.h>
#include <vector>

class ProcedureRangeProviderChain : public IRangeProvider {
public:
    ProcedureRangeProviderChain(ICapstoneProvider* cstoneInstanceProvider, IRangeProvider* baseRangeProvider, const std::vector<PatternScanConfig>& nestedProcedurePatterns);

    BufferView GetRange() override;

    Storage<std::unique_ptr<IProvider>> mProviders;
    std::vector<IRangeProvider*> mpRangeProviders;
};