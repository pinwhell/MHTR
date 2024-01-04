#include <OH/INestedLValueRValueWrapper.h>

void INestedLValueRValueWrapper::PushParentName(const std::string& parentName)
{
	mParentNames.push_back(parentName);
}

void INestedLValueRValueWrapper::PopParentName()
{
	mParentNames.pop_back();
}


std::string INestedLValueRValueWrapper::getFullName()
{
	if (mParentNames.size() < 1)
		return ILValueRValueWrapper::getFullName();

	std::string chainedParentNames = "";

	for (int i = 0; i < mParentNames.size(); i++)
		chainedParentNames += mParentNames[i] + ".";

	return chainedParentNames + ILValueRValueWrapper::getFullName();
}
