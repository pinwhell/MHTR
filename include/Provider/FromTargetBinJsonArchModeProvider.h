#pragma once

#include <Provider/IJson.h>
#include <Provider/IBinaryArchMode.h>
#include <CStone/ECStone.h>

class FromTargetBinJsonArchModeProvider : public IBinaryArchModeProvider {
public:
    FromTargetBinJsonArchModeProvider(IJsonProvider* binTargetProvider);

    ECapstoneArchMode GetBinaryArchMode() override;

    ECapstoneArchMode mMode;
};