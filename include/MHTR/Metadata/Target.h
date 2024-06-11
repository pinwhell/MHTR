#pragma once

#include <string>
#include <atomic>
#include <MHTR/Synther/INamespace.h>
#include <MHTR/Synther/NamespacedIdentifier.h>
#include <MHTR/Metadata/Result.h>

struct MetadataTarget {
	MetadataTarget(const std::string& name, INamespace* ns = nullptr);

	bool TrySetResult(const MetadataResult&& result);

	std::string GetName() const;
	std::string GetFullName() const;

	NamespacedIdentifier mFullIdentifier;
	std::atomic<bool> mHasResult;
	MetadataResult mResult;
};