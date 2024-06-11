#pragma once

#include <CStone/IProvider.h>

#include <MHTR/Provider/IProcedureEntry.h>
#include <MHTR/Provider/IRange.h>

namespace MHTR {
    class ProcedureRangeProvider : public IRangeProvider {
    public:
        ProcedureRangeProvider(ICapstoneProvider* cstoneProvider, IProcedureEntryProvider* procEntryProvider, size_t defProcSize = 0);

        Range GetRange() override;

        ICapstoneProvider* mCStoneProvider;
        IProcedureEntryProvider* mProcEntryProvider;
        size_t mDefProcSize;
    };
}