#pragma once

#include <Synther/INamespace.h>

class Namespace : public INamespace {
public:
    Namespace(const std::string& nsName, INamespace* nsParent = nullptr);

    std::string GetNamespace(bool bShowRootNs = false) const override;
    std::string GetFullNamespace(bool bShowRootNs = false) const override;
    bool GetIsRootNamespace() const override;

    INamespace* mNsParent;
    std::string mNsName;
};