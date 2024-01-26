#include <OH/ELF32BinaryFormat.h>
#include <OH/Arm32CapstoneHelperFactory.h>
#include <OH/Arm32ThumbCapstoneHelperFactory.h>

bool ELF32BinaryFormat::MakeCapstoneHelper(CapstoneHelperProvider* pProvider, ICapstoneHelper** outHelper, std::string mode)
{
	if (outHelper == nullptr)
		return false;

	*outHelper = nullptr;

	if (mode == "default")
		mode = "arm";

	if (mode == "arm")
		*outHelper = pProvider->getInstance(std::make_unique<Arm32CapstoneHelperFactory>());

	if (mode == "thumb")
		*outHelper = pProvider->getInstance(std::make_unique<Arm32ThumbCapstoneHelperFactory>());

	return *outHelper != nullptr;
}
