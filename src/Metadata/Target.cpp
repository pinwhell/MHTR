#include <MHTR/Metadata/Target.h>

MetadataTarget::MetadataTarget(const std::string& name, INamespace* ns)
	: mFullIdentifier(name, ns)
	, mResult(0)
	, mHasResult(false)
{}

bool MetadataTarget::TrySetResult(const MetadataResult&& result)
{
	bool _false = false;

	if (mHasResult.compare_exchange_strong(_false, true) == false)
		return false;

	mResult = result;

	return true;
}

std::string MetadataTarget::GetName() const
{
	return mFullIdentifier.mIdentifier;
}

std::string MetadataTarget::GetFullName() const
{
	return mFullIdentifier.GetFullIdentifier();
}
