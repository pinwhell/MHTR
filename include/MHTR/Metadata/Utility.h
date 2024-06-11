#pragma once

#include <set>
#include <string>

#include <MHTR/Metadata/Container.h>

namespace MHTR {

	using NamespaceSet = std::set<std::string>;

	NamespaceMetadataTargetSetMap NsMultiMetadataMapFromMultiMetadata(const MetadataTargetSet& targets);
	NamespaceSet AllNsFromMultiMetadataTarget(const MetadataTargetSet& targets);

}