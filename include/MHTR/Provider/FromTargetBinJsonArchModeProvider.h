#pragma once

#include <MHTR/Provider/IJson.h>
#include <MHTR/Provider/IBinaryArchMode.h>
#include <CStone/ECStone.h>

namespace MHTR {
    class FromTargetBinJsonArchModeProvider : public IBinaryArchModeProvider {
    public:
        FromTargetBinJsonArchModeProvider(IJsonProvider* binTargetProvider);

        ECapstoneArchMode GetBinaryArchMode() override;

        ECapstoneArchMode mMode;
    };
}