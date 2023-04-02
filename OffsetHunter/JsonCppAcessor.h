#pragma once

#include "IJsonAccesor.h"

class JsonCppAcessor : public IJsonAccesor {
public:
    std::string genGetInt() override;
    std::string genGetUInt() override;
};


