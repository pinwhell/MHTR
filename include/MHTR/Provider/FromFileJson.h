#pragma once

#include <string>
#include <MHTR/Provider/IJson.h>

namespace MHTR {

    class FromFileJsonProvider : public IJsonProvider {
    public:
        FromFileJsonProvider(const std::string& filePath);

        nlohmann::json* GetJson() override;

        nlohmann::json mJson;
    };

}