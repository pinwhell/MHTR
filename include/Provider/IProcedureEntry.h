#pragma once

#include <Provider/IProvider.h>
#include <cstdint>

class IProcedureEntryProvider : public IProvider {
public:
    virtual uint64_t GetEntry() = 0;
};