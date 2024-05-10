#pragma once

#include <CStone/ICapstone.h>

#include <Provider/IProcedureEntry.h>
#include <Provider/IRange.h>

class ProcedureRangeProvider : public IRangeProvider {
public:
    ProcedureRangeProvider(ICapstone* capstone, IProcedureEntryProvider* procEntryProvider);

    BufferView GetRange() override;

    ICapstone* mCapstone;
    IProcedureEntryProvider* mProcEntryProvider;
};