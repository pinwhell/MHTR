#include "Arm32ThumbCapstoneHelper.h"

Arm32ThumbCapstoneHelper::Arm32ThumbCapstoneHelper()
	: Arm32CapstoneHelper()
{
	setMode(CS_MODE_THUMB);
}
