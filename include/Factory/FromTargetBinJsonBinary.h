#pragma once

#include <string>

#include <Provider/IJson.h>
#include <Binary/IFactory.h>

class FromTargetBinJsonBinaryFactory : public IBinaryFactory {
public:
    FromTargetBinJsonBinaryFactory(IJsonProvider* _json);

    std::unique_ptr<IBinary> CreateBinary() override;

    std::string mPath;
};