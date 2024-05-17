#include <Synther/NamespacedIdentifier.h>

NamespacedIdentifier::NamespacedIdentifier(const std::string& identifier, INamespace* ns)
    : mIdentifier(identifier)
    , mNamespace(ns)
{}

std::string NamespacedIdentifier::GetFullIdentifier(bool bShowRootNs) const
{
    if (mNamespace == nullptr)
        return mIdentifier;

    return mNamespace->GetFullNamespace(bShowRootNs) + "::" + mIdentifier;
}