#pragma once

#include <MHTR/Provider/IProvider.h>

enum class ECapstoneArchMode;

namespace MHTR {

    class IBinaryArchModeProvider : public IProvider {
    public:
        virtual ~IBinaryArchModeProvider() = default;
        virtual ECapstoneArchMode GetBinaryArchMode() = 0;
    };
}