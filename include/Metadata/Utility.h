#pragma once

#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>

#include <Metadata/Target.h>

static std::unordered_map<std::string, std::vector<MetadataTarget*>> NsMultiMetadataMapFromMultiMetadata(const std::vector<MetadataTarget*>& targets)
{
	std::unordered_map<std::string, std::vector<MetadataTarget*>> result;

	for (auto* target : targets)
	{
		const INamespace* targetNs = target->mFullIdentifier.mNamespace;
		std::string targetNsStr = targetNs ? targetNs->GetNamespace() : METADATA_NS_NULL;

		if (result.find(targetNsStr) == result.end())
			result[targetNsStr] = std::vector<MetadataTarget*>();

		result[targetNsStr].push_back(target);
	}

	return result;
}

static std::unordered_set<std::string> AllNsFromMultiMetadataTarget(const std::vector<MetadataTarget*>& targets)
{
	std::unordered_set<std::string> result;

	std::transform(targets.begin(), targets.end(), std::inserter(result, result.end()), [](MetadataTarget* target) {
		INamespace* ns = target->mFullIdentifier.mNamespace;
		return ns ? ns->GetNamespace() : METADATA_NS_NULL;
		});

	return result;
}