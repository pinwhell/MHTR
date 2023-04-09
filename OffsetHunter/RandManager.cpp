#include "RandManager.h"

#include <stdlib.h>
#include <time.h>

void RandManager::InitRand()
{
	srand(time(NULL));
}

uint32_t RandManager::genLargeUint32()
{
    uint32_t random_number = 0;

    for (int i = 0; i < 4; i++) {
        random_number |= rand();
        if (i != 3) {
            random_number <<= 8;
        }
    }

    return random_number;
}


