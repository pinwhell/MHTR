#include "ELF32BinaryFormat.h"
#include "Arm32CapstoneHelperFactory.h"

bool ELF32BinaryFormat::MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper)
{
	if (outHelper == nullptr)
		return false;

	*outHelper = pProvider->getInstance(std::make_unique<Arm32CapstoneHelperFactory>());

	return *outHelper != nullptr;
}
