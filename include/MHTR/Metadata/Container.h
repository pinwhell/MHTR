#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <MHTR/Metadata/Target.h>

using MetadataTargetSet = std::unordered_set<MetadataTarget*>;
using NamespaceMetadataTargetSetMap = std::unordered_map<std::string, MetadataTargetSet>;