#pragma once

#include <CStone/ICapstone.h>

#include <Provider/IProcedureEntry.h>
#include <Provider/IAddresses.h>

class AsmExtractedProcedureEntryProvider : public IProcedureEntryProvider {
public:

    AsmExtractedProcedureEntryProvider(ICapstone* capstone, IAddressesProvider* adressesProvider);

    uint64_t GetEntry() override;

    ICapstone* mCapstone;
    IAddressesProvider* mAddressesProvider;
};