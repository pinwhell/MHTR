#pragma once

#include <MHTR/ILookable.h>
#include <MHTR/Metadata/Target.h>

class ILookableMetadata : public ILookable {
public:
	virtual ~ILookableMetadata() = default;
	virtual MetadataTarget* GetTarget() = 0;
};