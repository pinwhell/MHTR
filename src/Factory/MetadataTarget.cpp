#include <fmt/format.h>
#include <MHTR/Factory/MetadataTarget.h>

using namespace MHTR;

MetadataTarget* MetadataTargetFactory::GetMetadataTarget(const std::string& name, INamespace* ns)
{
    std::string fullyQualifiedName = fmt::format("{}{}", ns ? ns->GetNamespace() + "::" : "", name);

    if (mMetadataTargetMap.find(fullyQualifiedName) != mMetadataTargetMap.end())
        return mMetadataTargetMap[fullyQualifiedName].get();

    mMetadataTargetMap[fullyQualifiedName] = std::make_unique<MetadataTarget>(name, ns);

    return mMetadataTargetMap[fullyQualifiedName].get();
}
