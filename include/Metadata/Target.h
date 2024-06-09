#pragma once

#include <string>
#include <Synther/INamespace.h>
#include <Synther/NamespacedIdentifier.h>
#include <Metadata/Result.h>
#include <atomic>

struct MetadataTarget {
	MetadataTarget(const std::string& name, INamespace* ns = nullptr);

	bool TrySetResult(const MetadataResult&& result);

	std::string GetName() const;
	std::string GetFullName() const;

	NamespacedIdentifier mFullIdentifier;
	std::atomic<bool> mHasResult;
	MetadataResult mResult;
};