#include "IOffset.h"

bool IOffset::Init()
{
	if (mOffsetInfo.Init() == false)
		return false;

	return true;
}

void IOffset::setMetadata(const JsonValueWrapper& metadata)
{
	mOffsetInfo.setMetadata(metadata);
}

void IOffset::setParent(SingleDumpTarget* parent)
{
	mParent = parent;
}
