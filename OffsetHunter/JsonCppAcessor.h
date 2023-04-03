#pragma once

#include "IJsonAccesor.h"

class JsonCppAcessor : public IJsonAccesor {
public:
    std::string genGetInt(const std::string& key, uint32_t xorend = 0x0) override;
    std::string genGetUInt(const std::string& key, uint32_t xorend = 0x0) override;
    std::string getGlobalInclude() override;
    std::string getJsonObjFullType() override;
};


