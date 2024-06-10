#pragma once

#include <string>
#include <vector>
#include <algorithm>
#include <iterator>
#include <set>

#include <Metadata/Container.h>
#include <Metadata/Target.h>

using NamespaceSet = std::set<std::string>;

static NamespaceMetadataTargetSetMap NsMultiMetadataMapFromMultiMetadata(const MetadataTargetSet& targets)
{
	NamespaceMetadataTargetSetMap result;

	for (auto* target : targets)
	{
		const INamespace* targetNs = target->mFullIdentifier.mNamespace;
		std::string targetNsStr = targetNs ? targetNs->GetNamespace() : METADATA_NS_NULL;
		result[targetNsStr].insert(target);
	}

	return result;
}

static NamespaceSet AllNsFromMultiMetadataTarget(const MetadataTargetSet& targets)
{
	NamespaceSet result;

	std::transform(targets.begin(), targets.end(), std::inserter(result, result.end()), [](MetadataTarget* target) {
		INamespace* ns = target->mFullIdentifier.mNamespace;
		return ns ? ns->GetNamespace() : METADATA_NS_NULL;
		});

	return result;
}