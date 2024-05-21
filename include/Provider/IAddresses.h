#pragma once

#include <Provider/IProvider.h>
#include <cstdint>
#include <vector>

class IAddressesProvider : public IProvider {
public:
    virtual std::vector<uint64_t> GetAllAddresses() = 0;
};