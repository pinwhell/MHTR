#pragma once

#include <string>

class INamespace {
public:
    virtual std::string GetNamespace(bool bShowRootNs = false) const = 0;
    virtual std::string GetFullNamespace(bool bShowRootNs = false) const = 0;
    virtual bool GetIsRootNamespace() const = 0;
};