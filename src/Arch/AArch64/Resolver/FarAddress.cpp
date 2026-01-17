#include <CStone/Arch/AArch64/Utility.h>
#include <MHTR/Arch/AArch64/Resolver/FarAddress.h>

#include <stdexcept>
#include <capstone/capstone.h>
#include <capstone/arm64.h>

using namespace MHTR;

AArch64FarAddressResolver::AArch64FarAddressResolver(ICapstoneProvider* cstoneProvider)
    : mCStoneProvider(cstoneProvider)
{}

uint64_t AArch64FarAddressResolver::TryResolve(uint64_t at, bool bDerref)
{
    return (uint64_t)AArch64FarPcRelLEATryResolve(mCStoneProvider->GetInstance(), (void*)at, bDerref);
}
