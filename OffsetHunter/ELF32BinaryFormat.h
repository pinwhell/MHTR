#pragma once

#include "IBinaryFormat.h"
#include "ELF.h"

class ELF32BinaryFormat : public IBinaryFormatImpl<elf32_hdr>
{
private:

public:
	bool MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper) override;
};

