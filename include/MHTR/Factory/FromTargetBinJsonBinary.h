#pragma once

#include <string>

#include <MHTR/Provider/IJson.h>
#include <MHTR/Binary/IFactory.h>

class FromTargetBinJsonBinaryFactory : public IBinaryFactory {
public:
    FromTargetBinJsonBinaryFactory(IJsonProvider* _json);

    std::unique_ptr<IBinary> CreateBinary() override;

    std::string mPath;
};