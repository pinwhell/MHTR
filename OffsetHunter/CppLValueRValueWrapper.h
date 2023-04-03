#pragma once
#include "ILValueRValueWrapper.h"

class CppLValueRValueWrapper : public ILValueRValueWrapper
{
public:
    std::string getSyntaxTerminator() override;
};

