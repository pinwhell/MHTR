#pragma once

#include <cstdint>
#include <vector>
#include <MHTR/Provider/IProvider.h>

class IAddressesProvider : public IProvider {
public:
    virtual std::vector<uint64_t> GetAllAddresses() = 0;
};