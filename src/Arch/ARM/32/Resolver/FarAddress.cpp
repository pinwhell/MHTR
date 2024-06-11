#include <CStone/Arch/ARM/32/Utility.h>
#include <MHTR/Arch/ARM/32/Resolver/FarAddress.h>

using namespace MHTR;

ARM32FarAddressResolver::ARM32FarAddressResolver(ICapstoneProvider* cstoneProvider)
    : mCStoneProvider(cstoneProvider)
{}

uint64_t ARM32FarAddressResolver::TryResolve(uint64_t at, bool bDerref)
{
    return (uint64_t)ARM32FarPcRelLEATryResolve(mCStoneProvider->GetInstance(), (void*)at, bDerref);
}