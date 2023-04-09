#pragma once

#include <cstdint>

class RandManager
{
public:
	static void InitRand();
	static uint32_t genLargeUint32();
};

