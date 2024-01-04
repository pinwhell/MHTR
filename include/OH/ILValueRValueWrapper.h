#pragma once

#include <string>

class ILValueRValueWrapper
{
private:

    bool mAddTerminator;
    std::string mType;
    std::string mName;
    std::string mValue;

public:
    ILValueRValueWrapper();

    virtual std::string getFullName();
    void setType(const std::string& type);
    void setName(const std::string& name);
    void setValue(const std::string& value);
    virtual std::string ComputeDeclaration();
    virtual std::string ComputeDefinition();
    virtual std::string ComputeDefinitionAndDeclaration();
    virtual std::string getSyntaxTerminator();
    std::string getTermninator();
    void setAddTerminator(bool b);
};

