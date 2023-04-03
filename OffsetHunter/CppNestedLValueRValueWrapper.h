#pragma once

#include "INestedLValueRValueWrapper.h"
#include <string>

class CppNestedLValueRValueWrapper : public INestedLValueRValueWrapper
{
public:
	std::string getSyntaxTerminator() override;
};

