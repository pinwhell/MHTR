#pragma once

#include <CStone/ICapstone.h>

#include <IProcedureEntryProvider.h>
#include <IRangeProvider.h>

class ProcedureRangeProvider : public IRangeProvider {
public:
    ProcedureRangeProvider(ICapstone* capstone, IProcedureEntryProvider* procEntryProvider);

    BufferView GetRange() override;

    ICapstone* mCapstone;
    IProcedureEntryProvider* mProcEntryProvider;
};