#pragma once

#include <Provider/IJson.h>

class JsonProvider : public IJsonProvider {
public:
    JsonProvider(const char* jsonSrc);
    JsonProvider(const  nlohmann::json& json);

    nlohmann::json* GetJson() override;

    nlohmann::json mJson;
};