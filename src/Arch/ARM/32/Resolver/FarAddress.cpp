#include <Arch/ARM/32/Resolver/FarAddress.h>
#include <CStone/Arch/ARM/32/Utility.h>

ARM32FarAddressResolver::ARM32FarAddressResolver(ICapstone* capstone)
    : mCapstone(capstone)
{}

uint64_t ARM32FarAddressResolver::TryResolve(uint64_t at, bool bDerref)
{
    return (uint64_t)ARM32FarPcRelLEATryResolve(mCapstone, (void*)at, bDerref);
}