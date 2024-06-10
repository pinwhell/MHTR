#pragma once

#include <set>
#include <string>

#include <Metadata/Container.h>

using NamespaceSet = std::set<std::string>;

NamespaceMetadataTargetSetMap NsMultiMetadataMapFromMultiMetadata(const MetadataTargetSet& targets);
NamespaceSet AllNsFromMultiMetadataTarget(const MetadataTargetSet& targets);