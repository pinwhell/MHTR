#pragma once
#include "ILValueRValueWrapper.h"

#include <vector>
#include <string>

class INestedLValueRValueWrapper : public ILValueRValueWrapper
{
private:
	std::vector<std::string> mParentNames;
public:

	void PushParentName(const std::string& parentName);
	void PopParentName();

	std::string getFullName() override;
};

