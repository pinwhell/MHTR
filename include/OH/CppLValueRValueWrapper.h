#pragma once
#include <OH/ILValueRValueWrapper.h>

class CppLValueRValueWrapper : public ILValueRValueWrapper
{
public:
    std::string getSyntaxTerminator() override;
};

