#pragma once

#include <CStone/IProvider.h>

#include <Provider/IProcedureEntry.h>
#include <Provider/IAddresses.h>

class AsmExtractedProcedureEntryProvider : public IProcedureEntryProvider {
public:

    AsmExtractedProcedureEntryProvider(ICapstoneProvider* cstoneProvider, IAddressesProvider* adressesProvider);

    uint64_t GetEntry() override;

    ICapstoneProvider* mCStoneProvider;
    IAddressesProvider* mAddressesProvider;
};