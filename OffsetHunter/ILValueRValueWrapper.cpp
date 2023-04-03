#include "ILValueRValueWrapper.h"

ILValueRValueWrapper::ILValueRValueWrapper()
{
    mAddTerminator = true;
}

std::string ILValueRValueWrapper::getFullName()
{
    return mName;
}

void ILValueRValueWrapper::setType(const std::string& type)
{
    mType = type;
}

void ILValueRValueWrapper::setName(const std::string& name)
{
    mName = name;
}

void ILValueRValueWrapper::setValue(const std::string& value)
{
    mValue = value;
}

std::string ILValueRValueWrapper::ComputeDeclaration() {
    return mType + " " + mName + getTermninator();
}

std::string ILValueRValueWrapper::ComputeDefinition() {
    return  getFullName() + " = " + mValue + getTermninator();
}

std::string ILValueRValueWrapper::ComputeDefinitionAndDeclaration() {
    return  mType + " " + mName + " = " + mValue + getTermninator();
}

std::string ILValueRValueWrapper::getSyntaxTerminator()
{
    return "";
}

std::string ILValueRValueWrapper::getTermninator()
{
    return mAddTerminator ? getSyntaxTerminator() : "";
}

void ILValueRValueWrapper::setAddTerminator(bool b)
{
    mAddTerminator = b;
}
