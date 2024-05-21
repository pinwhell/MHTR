#pragma once

#include <CStone/IProvider.h>

#include <Provider/IProcedureEntry.h>
#include <Provider/IRange.h>

class ProcedureRangeProvider : public IRangeProvider {
public:
    ProcedureRangeProvider(ICapstoneProvider* cstoneProvider, IProcedureEntryProvider* procEntryProvider);

    BufferView GetRange() override;

    ICapstoneProvider* mCStoneProvider;
    IProcedureEntryProvider* mProcEntryProvider;
};