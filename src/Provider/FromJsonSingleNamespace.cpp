#include <Provider/FromJsonSingleNamespace.h>

FromJsonSingleNamespaceProvider::FromJsonSingleNamespaceProvider(IJsonProvider* jsonProvider)
    : mNs(jsonProvider->GetJson()->contains("namespace") ? (*jsonProvider->GetJson())["namespace"].get<std::string>() : "")
{}

INamespace* FromJsonSingleNamespaceProvider::GetNamespace()
{
    return &mNs;
}
