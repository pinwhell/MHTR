#pragma once

#include <Synther/Identifier.h>
#include <Synther/INamespace.h>

class NamespacedIdentifier {
public:
    NamespacedIdentifier(const std::string& identifier, INamespace* ns = nullptr);

    std::string GetFullIdentifier(bool bShowRootNs = false) const;

    std::string mIdentifier;
    INamespace* mNamespace;
};