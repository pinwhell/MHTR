#pragma once

#include "IBinaryFormat.h"
#include "ELF.h"

class ELF32BinaryFormat : public IBinaryFormatImpl<Elf32_Ehdr>
{
private:

public:
	bool MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper, std::string mode = "default") override;
};

