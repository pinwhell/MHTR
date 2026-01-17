#pragma once

#include <vector>
#include <MHTR/Storage.h>
#include <MHTR/Provider/IRange.h>
#include <MHTR/FunctionScanConfig.h>
#include <CStone/IProvider.h>

namespace MHTR {
    class ProcedureRangeProviderChain : public IRangeProvider {
    public:
        ProcedureRangeProviderChain(IRangeProvider* baseRangeProvider, const std::vector<FunctionScanConfig>& nestedProcedurePatterns);

        Range GetRange() override;

        Storage<std::unique_ptr<IProvider>> mProviders;
        std::vector<IRangeProvider*> mpRangeProviders;
    };
}