#pragma once
#include "ICapstoneHelper.h"
class Arm32CapstoneHelper : public ICapstoneHelper
{
public:
	Arm32CapstoneHelper();


	bool PCRelInstAddrRebaseRoot();

	bool InterpretDispInst(cs_insn* pInst, uintptr_t& outDisp) override;
	bool InterpretDispPCRelativeInst(cs_insn* pInst, cs_insn* pInstEnd, uintptr_t& outDisp) override;
	bool GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest) override;
	bool IsIntructionReturnRelated(cs_insn* pInst) override;
};

