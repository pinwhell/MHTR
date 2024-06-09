#pragma once

#include <unordered_map>
#include <string>
#include <vector>

#include <Metadata/Target.h>

static std::unordered_map<std::string, std::vector<MetadataTarget*>> TargetsGetNamespacedMap(const std::vector<MetadataTarget*>& targets)
{
	std::unordered_map<std::string, std::vector<MetadataTarget*>> result;

	for (auto* target : targets)
	{
		const INamespace* targetNs = target->mFullIdentifier.mNamespace;
		std::string targetNsStr = targetNs ? targetNs->GetNamespace() : METADATA_NULL_NS;

		if (result.find(targetNsStr) == result.end())
			result[targetNsStr] = std::vector<MetadataTarget*>();

		result[targetNsStr].push_back(target);
	}

	return result;
}