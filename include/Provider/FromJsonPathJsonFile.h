#pragma once

#include <Provider/IJson.h>
#include <Provider/FromFileJson.h>

class FromJsonPathJsonFileProvider : public IJsonProvider {
public:
    FromJsonPathJsonFileProvider(IJsonProvider* jsonContainingPath, const std::string& jsonPathKey = "path");

    nlohmann::json* GetJson() override;

    FromFileJsonProvider mProvider;
};