#pragma once

#include <ILookable.h>
#include <Metadata/Target.h>

class ILookableMetadata : public ILookable {
public:
	virtual ~ILookableMetadata() = default;
	virtual MetadataTarget* GetTarget() = 0;
};