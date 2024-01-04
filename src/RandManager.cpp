#include <OH/RandManager.h>

#include <stdlib.h>
#include <time.h>
#include <thread>

void RandManager::InitRand()
{
    static bool bInitialized = false;

    if (bInitialized == true)
        return;

    const auto thizThreadId = std::this_thread::get_id();
    const auto hasher = std::hash<std::thread::id>();

	srand(time(NULL) * hasher(thizThreadId));

    bInitialized = true;
}

uint32_t RandManager::genLargeUint32()
{
    InitRand();

    uint32_t random_number = 0;

    for (int i = 0; i < 4; i++) {
        random_number |= rand();
        if (i != 3) {
            random_number <<= 8;
        }
    }

    return random_number;
}


