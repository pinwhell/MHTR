#pragma once

#include <cstdint>
#include <MHTR/Provider/IProvider.h>

namespace MHTR {
    class IProcedureEntryProvider : public IProvider {
    public:
        virtual uint64_t GetEntry() = 0;
    };
}