#pragma once

#include <cstdint>
#include <MHTR/Provider/IProvider.h>

class IProcedureEntryProvider : public IProvider {
public:
    virtual uint64_t GetEntry() = 0;
};