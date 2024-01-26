#pragma once

#include "IBinaryFormat.h"
#include "ELF.h"

class ELF64BinaryFormat : public IBinaryFormatImpl<Elf64_Ehdr>
{
private:

public:
	bool MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper, std::string mode = "default") override;
};

