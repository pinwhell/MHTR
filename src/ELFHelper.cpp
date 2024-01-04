#include <OH/ELFHelper.h>
#include <string.h>

bool ELFHelper::IsELF(unsigned char* base)
{
	if (base == nullptr)
		return false;

	return !memcmp(base, ELFMAG, SELFMAG);
}

bool ELFHelper::Is32(unsigned char* _base)
{
	union {
		Elf32_Ehdr* pElfBase;
		unsigned char* base;
	};

	base = _base;

	return pElfBase->e_ident[EI_CLASS] == ELFCLASS32;
}
