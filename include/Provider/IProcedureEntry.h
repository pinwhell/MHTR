#pragma once

#include <cstdint>

class IProcedureEntryProvider {
public:
    virtual uint64_t GetEntry() = 0;
};