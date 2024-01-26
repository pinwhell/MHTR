#include <OH/ELF64BinaryFormat.h>
#include <OH/Arm64CapstoneHelperFactory.h>

bool ELF64BinaryFormat::MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper, std::string mode)
{
	if (outHelper == nullptr)
		return false;

	*outHelper = nullptr;

	if (mode == "default")
		mode = "arm";

	if (mode == "arm")
		*outHelper = pProvider->getInstance(std::make_unique<Arm64CapstoneHelperFactory>());

	return *outHelper != nullptr;
}
