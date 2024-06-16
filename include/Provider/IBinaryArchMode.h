#pragma once

#include <Provider/IProvider.h>

enum class ECapstoneArchMode;

class IBinaryArchModeProvider : public IProvider {
public:
    virtual ~IBinaryArchModeProvider() = default;
    virtual ECapstoneArchMode GetBinaryArchMode() = 0;
};