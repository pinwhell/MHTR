#pragma once

#include <nlohmann/json.hpp>

class IJsonProvider {
public:
    virtual ~IJsonProvider() {}
    virtual nlohmann::json* GetJson() = 0;
};