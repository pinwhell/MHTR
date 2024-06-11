#pragma once

#include <cstdint>
#include <vector>
#include <MHTR/Provider/IProvider.h>

namespace MHTR {

    class IAddressesProvider : public IProvider {
    public:
        virtual std::vector<uint64_t> GetAllAddresses() = 0;
    };

}