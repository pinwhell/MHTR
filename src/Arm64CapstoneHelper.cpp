#include <OH/Arm64CapstoneHelper.h>
#include <OH/CapstoneAux.h>

Arm64CapstoneHelper::Arm64CapstoneHelper()
{
	setArch(CS_ARCH_ARM64);
	setMode(CS_MODE_ARM);
}

bool Arm64CapstoneHelper::GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest)
{
	if (pInst->id == ARM64_INS_B ||
		pInst->id == ARM64_INS_BL)
	{
		outDest = pInst->detail->arm64.operands[0].imm;
		return true;
	}

	return false;
}

bool Arm64CapstoneHelper::IsIntructionReturnRelated(cs_insn* pInst)
{
	return Arm64CapstoneAux::HeuristicReturn(pInst);
}

bool Arm64CapstoneHelper::IsIntructionPrologRelated(cs_insn* pInst)
{
	if (pInst->id == ARM64_INS_SUB && Arm64CapstoneAux::RegisterPresent(pInst, ARM64_REG_SP))
		return true;

	return false;
}

bool Arm64CapstoneHelper::InstDisasmFollow(cs_insn* pInstBegin, cs_insn* pInstEnd, uintptr_t& outLocation)
{
	return false;
}

bool Arm64CapstoneHelper::GetInstructionDisp(cs_insn* pInst, uintptr_t& outDisp)
{
    switch (pInst->id)
    {

    case ARM64_INS_LDR:
    case ARM64_INS_LDRH:
    case ARM64_INS_LDRB:
    case ARM64_INS_LDRSB:
    case ARM64_INS_LDRSH:
    case ARM64_INS_LDRSW:
    {
        //if (ArmCapstoneAux::GetRValueRegType(pInst) == ARM64_REG_B0) return DisasmTrySolvePositionIndependentAddress(pInst, outDisp);
        outDisp = pInst->detail->arm64.operands[pInst->detail->arm64.op_count - 1].mem.disp;
    } break;

    case ARM64_INS_STR:
    case ARM64_INS_STRH:
    case ARM64_INS_STRB:
    {
        outDisp = pInst->detail->arm64.operands[pInst->detail->arm64.op_count - 1].mem.disp;
    } break;

    case ARM64_INS_ADD:
    case ARM64_INS_SUB:
    {
        outDisp = pInst->detail->arm64.operands[pInst->detail->arm64.op_count - 1].imm;
    }break;

    case ARM64_INS_MOV:
    {
        auto op = pInst->detail->arm64.operands[pInst->detail->arm64.op_count - 1];

        if (op.type == ARM64_OP_IMM)
        {
            outDisp = op.imm;
            break;
        }
    }break;

    case ARM64_INS_MVN:
    {
        auto op = pInst->detail->arm64.operands[pInst->detail->arm64.op_count - 1];

        if (op.type == ARM64_OP_IMM)
        {
            outDisp = ~(op.imm);
            break;
        }
    }break;

    default:
        return false;
    }

    return true;
}

bool Arm64CapstoneHelper::SolvePositionIndependentAddress(cs_insn* pInst, cs_insn* pInstEnd, uintptr_t& outDisp)
{
	return false;
}

uint64_t Arm64CapstoneHelper::getPcFromInstruction(cs_insn* inst)
{
	return inst->address + inst[0].size + inst[1].size;
}
