#include <CStone/Arch/ARM/64/Utility.h>
#include <MHTR/Arch/ARM/64/Resolver/FarAddress.h>

#include <stdexcept>
#include <capstone/capstone.h>
#include <capstone/arm64.h>

using namespace MHTR;

ARM64FarAddressResolver::ARM64FarAddressResolver(ICapstoneProvider* cstoneProvider)
    : mCStoneProvider(cstoneProvider)
{}

uint64_t ARM64FarAddressResolver::TryResolve(uint64_t at, bool bDerref)
{
    return (uint64_t)ARM64FarPcRelLEATryResolve(mCStoneProvider->GetInstance(), (void*)at, bDerref);
}
