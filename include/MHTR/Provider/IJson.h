#pragma once

#include <nlohmann/json.hpp>

namespace MHTR {
    class IJsonProvider {
    public:
        virtual ~IJsonProvider() {}
        virtual nlohmann::json* GetJson() = 0;
    };
}