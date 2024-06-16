#pragma once

#include <string>

#include <MHTR/Provider/IJson.h>
#include <MHTR/Binary/IFactory.h>
#include <MHTR/Provider/IBinaryArchMode.h>

namespace MHTR {
    class FromTargetBinJsonBinaryFactory : public IBinaryFactory {
    public:
        FromTargetBinJsonBinaryFactory(IJsonProvider* _json, IBinaryArchModeProvider* binaryArchModeProvider = 0);

        std::unique_ptr<IBinary> CreateBinary() override;

        std::string mPath;
        IBinaryArchModeProvider* mArchModeProvider;
    };
}