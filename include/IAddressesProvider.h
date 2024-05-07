#pragma once

#include <cstdint>
#include <vector>

class IAddressesProvider {
public:
    virtual std::vector<uint64_t> GetAllAddresses() = 0;
};