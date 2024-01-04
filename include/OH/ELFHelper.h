#pragma once

#include "ELF.h"

class ELFHelper
{
public:
	static bool IsELF(unsigned char* base);
	static bool Is32(unsigned char* base);
};

