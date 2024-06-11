#pragma once

#include <CStone/IProvider.h>

#include <MHTR/Provider/IProcedureEntry.h>
#include <MHTR/Provider/IAddresses.h>

class AsmExtractedProcedureEntryProvider : public IProcedureEntryProvider {
public:

    AsmExtractedProcedureEntryProvider(ICapstoneProvider* cstoneProvider, IAddressesProvider* adressesProvider);

    uint64_t GetEntry() override;

    ICapstoneProvider* mCStoneProvider;
    IAddressesProvider* mAddressesProvider;
};