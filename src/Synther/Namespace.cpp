#include <Synther/Namespace.h>

Namespace::Namespace(const std::string& nsName, INamespace* nsParent)
    : mNsParent(nsParent)
    , mNsName(nsName)
{}

std::string Namespace::GetNamespace(bool bShowRootNs) const {
    if (GetIsRootNamespace() && bShowRootNs)
        return  "::" + mNsName;

    return mNsName;
}

std::string Namespace::GetFullNamespace(bool bShowRootNs) const
{
    if (!GetIsRootNamespace())
        return mNsParent->GetFullNamespace(bShowRootNs) + "::" + mNsName;

    return bShowRootNs ? "::" + mNsName : mNsName;
}

bool Namespace::GetIsRootNamespace() const
{
    return mNsParent == nullptr;
}