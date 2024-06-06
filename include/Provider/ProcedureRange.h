#pragma once

#include <CStone/IProvider.h>

#include <Provider/IProcedureEntry.h>
#include <Provider/IRange.h>

class ProcedureRangeProvider : public IRangeProvider {
public:
    ProcedureRangeProvider(ICapstoneProvider* cstoneProvider, IProcedureEntryProvider* procEntryProvider, size_t defProcSize = 0);

    Range GetRange() override;

    ICapstoneProvider* mCStoneProvider;
    IProcedureEntryProvider* mProcEntryProvider;
    size_t mDefProcSize;
};