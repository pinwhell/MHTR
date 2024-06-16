#pragma once

#include <string>

#include <Provider/IJson.h>
#include <Binary/IFactory.h>
#include <Provider/IBinaryArchMode.h>

class FromTargetBinJsonBinaryFactory : public IBinaryFactory {
public:
    FromTargetBinJsonBinaryFactory(IJsonProvider* _json, IBinaryArchModeProvider* binaryArchModeProvider = 0);

    std::unique_ptr<IBinary> CreateBinary() override;

    std::string mPath;
    IBinaryArchModeProvider* mArchModeProvider;
};