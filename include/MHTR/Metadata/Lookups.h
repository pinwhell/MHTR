#pragma once

#include <string>
#include <stdexcept>
#include <MHTR/ILookableMetadata.h>
#include <MHTR/Provider/IRange.h>
#include <MHTR/Provider/IAddresses.h>
#include <MHTR/IOffsetCalculator.h>
#include <CStone/IProvider.h>

class MetadataLookupException : public std::runtime_error {
public:
	MetadataLookupException(const std::string& what);
};

class PatternCheckLookup : public ILookableMetadata {
public:
	PatternCheckLookup(MetadataTarget& target, IRangeProvider* scanRange, const std::string& pattern, bool bUniqueLookup = true);

	void Lookup() override;
	MetadataTarget* GetTarget() override;

	MetadataTarget& mTarget;
	IRangeProvider* mScanRange;
	std::string mPattern;
	bool mbUniqueLookup;

private:
	void Check();
};

class PatternSingleResultLookup : public ILookableMetadata {
public:
	PatternSingleResultLookup(MetadataTarget& target, IRangeProvider* scanRange, IOffsetCalculator* offsetCalculator, const std::string& pattern);

	void Lookup() override;
	MetadataTarget* GetTarget() override;

	MetadataTarget& mTarget;
	IRangeProvider* mScanRange;
	IOffsetCalculator* mOffsetCalculator;
	std::string mPattern;
};

class InsnImmediateLookup : public ILookableMetadata {
public:
	InsnImmediateLookup(MetadataTarget& target, IAddressesProvider* insnAddrsProvider, ICapstoneProvider* cstoneProvider, size_t immIndex = 0);

	void Lookup() override;
	MetadataTarget* GetTarget() override;

	IAddressesProvider* mInsnAddrsProvider;
	ICapstoneProvider* mCStoneProvider;
	MetadataTarget& mTarget;
	size_t mImmIndex;
};

class HardcodedLookup : public ILookableMetadata {
public:
	HardcodedLookup(MetadataTarget& target, const MetadataResult& hardcoded);

	MetadataTarget* GetTarget() override;
	void Lookup() override;

	MetadataTarget& mTarget;
};
