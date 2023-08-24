#include "Arm32CapstoneHelper.h"
#include "CapstoneAux.h"

Arm32CapstoneHelper::Arm32CapstoneHelper()
{
	setArch(CS_ARCH_ARM);
	setMode(CS_MODE_ARM);
}

bool Arm32CapstoneHelper::PCRelInstAddrRebaseRoot()
{
	return false;
}

bool Arm32CapstoneHelper::GetInstructionDisp(cs_insn* pInst, uintptr_t& outDisp)
{
    switch (pInst->id)
    {
    
    case ARM_INS_LDR:
    case ARM_INS_LDRH:
    case ARM_INS_LDRD:
    case ARM_INS_LDRB:
    case ARM_INS_LDRBT:
    case ARM_INS_LDREXB:
    {
        if (ArmCapstoneAux::GetRValueRegType(pInst) == ARM_REG_PC) return DisasmTrySolvePositionIndependentAddress(pInst, outDisp);
        else outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_STR:
    case ARM_INS_STRH:
    case ARM_INS_STRB:
    case ARM_INS_STRD:
    case ARM_INS_STRBT:
    case ARM_INS_STREXB:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_VLDR:
    case ARM_INS_VSTR:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].mem.disp;
    } break;

    case ARM_INS_ADD:
    case ARM_INS_SUB:
    {
        outDisp = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1].imm;
    }break;

    case ARM_INS_MOV:
    case ARM_INS_MOVW:
    case ARM_INS_MOVT:
    {
        auto op = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1];

        if (op.type == ARM_OP_IMM)
        {
            outDisp = op.imm;
            break;
        }
    }

    case ARM_INS_MVN:
    {
        auto op = pInst->detail->arm.operands[pInst->detail->arm.op_count - 1];

        if (op.type == ARM_OP_IMM)
        {
            outDisp = ~(op.imm);
            break;
        }
    }

    default:
        return false;
    }

    return true;
}

bool Arm32CapstoneHelper::SolvePositionIndependentAddress(cs_insn* pInstBegin, cs_insn* pInstEnd, uintptr_t& outDisp)
{
    if ((pInstBegin + 1 < pInstEnd) == false)

        // We cant precisely calculate PC Relative

        return false;

    uint16_t regPcRelOffHolderType = ArmCapstoneAux::GetLValueRegType(pInstBegin);
    uintptr_t targetPcRelOff = *(uint32_t*)(getPcFromInstruction(pInstBegin) + pInstBegin->detail->arm.operands[pInstBegin->detail->arm.op_count - 1].mem.disp);

    for (auto* pCurrInst = pInstBegin + 1; pCurrInst < pInstEnd; pCurrInst++)
    {

        uint64_t currInstPc = getPcFromInstruction(pCurrInst);
        uint64_t currInstPcBinRelOff = currInstPc - mBase;

        switch (pCurrInst->id) {

        case ARM_INS_LDR:
        case ARM_INS_STR:
        {
            if (pCurrInst->detail->arm.operands[1].mem.base == ARM_REG_PC &&
                pCurrInst->detail->arm.operands[1].mem.index == regPcRelOffHolderType)
            {
                outDisp = currInstPcBinRelOff + targetPcRelOff;

                return true;
            }
        }break;

        case ARM_INS_ADD:
        {
            if ((   /*ADD R0, PC*/
                pCurrInst->detail->arm.operands[1].reg == ARM_REG_PC &&
                pCurrInst->detail->arm.operands[0].reg == regPcRelOffHolderType
            ) || 
            (       /*ADD R0, R0, PC*/
                pCurrInst->detail->arm.operands[2].reg == ARM_REG_PC &&
                pCurrInst->detail->arm.operands[1].reg == regPcRelOffHolderType
            ))
            {
                outDisp = currInstPcBinRelOff + targetPcRelOff;

                return true;
            }
        }break;

        }
    }

    return false;
}

bool Arm32CapstoneHelper::GetCallDestinationInst(cs_insn* pInst, uintptr_t& outDest)
{
    switch (pInst->id)
    {
    case ARM_INS_BL:
    case ARM_INS_B:
    {
        outDest = pInst->detail->arm.operands[0].imm;
        return true;
    }

    }
    return pInst->address;

    return false;
}

bool Arm32CapstoneHelper::IsIntructionReturnRelated(cs_insn* pInst)
{
    return ArmCapstoneAux::HeuristicReturn(pInst);
}

bool Arm32CapstoneHelper::IsIntructionPrologRelated(cs_insn* pInst)
{
    return ArmCapstoneAux::HeuristicProlog(pInst);
}

uint64_t Arm32CapstoneHelper::getPcFromInstruction(cs_insn* inst)
{
    return inst->address + inst[0].size + inst[1].size;
}


