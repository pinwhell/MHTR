#pragma once

#include <MHTR/Provider/IJson.h>
#include <MHTR/Provider/FromFileJson.h>

namespace MHTR {

    class FromJsonPathJsonFileProvider : public IJsonProvider {
    public:
        FromJsonPathJsonFileProvider(IJsonProvider* jsonContainingPath, const std::string& jsonPathKey = "path");

        nlohmann::json* GetJson() override;

        FromFileJsonProvider mProvider;
    };

}