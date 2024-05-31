#pragma once

#include <Provider/IJson.h>
#include <string>

class FromFileJsonProvider : public IJsonProvider {
public:
    FromFileJsonProvider(const std::string& filePath);

    nlohmann::json* GetJson() override;

    nlohmann::json mJson;
};