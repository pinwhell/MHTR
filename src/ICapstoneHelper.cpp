#include <OH/ICapstoneHelper.h>

ICapstoneHelper::ICapstoneHelper()
{
    setMode(CS_MODE_LITTLE_ENDIAN);
}

ICapstoneHelper::~ICapstoneHelper()
{
    if (mHandle != 0x0)
        cs_close(&mHandle);
}

bool ICapstoneHelper::Init()
{
    if (cs_open(mArch, mMode, &mHandle) != CS_ERR_OK)
        return false;

    if (cs_option(mHandle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
        return false;

    return true;
}

void ICapstoneHelper::setArch(cs_arch arch)
{
    mArch = arch;
}

void ICapstoneHelper::setMode(cs_mode mode)
{
    mMode = mode;
}

bool ICapstoneHelper::TryGetCallDestination(const unsigned char* pInst, uintptr_t& outDest)
{
    cs_insn* pDisasmdInst = nullptr;
    uintptr_t count = 0;
    bool result = false;

    if ((count = cs_disasm(mHandle, pInst, 0x4, (uint64_t)(pInst), 0, &pDisasmdInst)) != 0 && pDisasmdInst) // Refactor code size in the future
    {
        result = GetCallDestinationInst(pDisasmdInst, outDest);
        cs_free(pDisasmdInst, count);
    }

    return result;
}


bool ICapstoneHelper::InstDisasmTryGetDisp(const unsigned char* pInst, uintptr_t& outDisp)
{
    cs_insn* pDisasmdInst = nullptr;
    uintptr_t count = 0;
    bool result = false;

    if ((count = cs_disasm(mHandle, pInst, 0x4, (uint64_t)(pInst), 0, &pDisasmdInst)) != 0 && pDisasmdInst)
    {
        result = GetInstructionDisp(pDisasmdInst, outDisp);
        cs_free(pDisasmdInst, count);
    }

    return result;
}

bool ICapstoneHelper::DisasmTrySolvePositionIndependentAddress(cs_insn* pInst, uintptr_t& outDisp)
{
    cs_insn* pDisasmdInst = nullptr;
    

    size_t dismInstCnt = cs_disasm(
        mHandle,
        (uint8_t*)pInst->address,
        0x50,
        PCRelInstAddrRebaseRoot() ?
        (pInst->address - mBase) :
        pInst->address,
        0,
        &pDisasmdInst
    );

    if (dismInstCnt < 1 || pDisasmdInst == nullptr)
        return false;

    bool result = SolvePositionIndependentAddress(pDisasmdInst, pDisasmdInst + dismInstCnt, outDisp);

    cs_free(pDisasmdInst, dismInstCnt);

    return result;
}

bool ICapstoneHelper::TryComputeParagraphSize(const unsigned char* pInst, uintptr_t& outSize)
{
    cs_insn pDisasmdInst{ 0 };
    cs_detail pDisasmdDetail{ 0 };
    pDisasmdInst.detail = &pDisasmdDetail;
    uintptr_t count = 0;
    bool result = false;
    uint64_t addr = (uint64_t)pInst;
    const unsigned char* pCurrInst = pInst;
    size_t szRem = ((size_t)mpBase + mBaseSize) - addr;

    bool bIsFirstProlog = true;

    while (cs_disasm_iter(mHandle, (const uint8_t**)&pCurrInst, &szRem, (uint64_t*)&addr, &pDisasmdInst))
    {
        result = true;

        outSize = (pDisasmdInst.address + pDisasmdInst.size) - (uint64_t)pInst;

        if (IsIntructionPrologRelated(&pDisasmdInst))
        {
            // if is not the first prolog it means a new one is starting
            // Maybe the function we are evaluating somehow got control out but without any return instructiuno signs
            if(bIsFirstProlog == false)
                break;

            bIsFirstProlog = false;
        }

        if (IsIntructionReturnRelated(&pDisasmdInst))
            break;
    }

    return result;
}

void ICapstoneHelper::setBaseAddress(unsigned char* base)
{
    mpBase = base;
}

void ICapstoneHelper::setBaseSize(size_t sz)
{
    mBaseSize = sz;
}

void ICapstoneHelper::ForEachInstructionAbs(const unsigned char* startAt, std::function<bool(cs_insn* pInst)> callback)
{
    cs_insn pDisasmdInst{ 0 };
    cs_detail pDisasmdDetail{ 0 };

    uint64_t addr = (uint64_t)startAt;
    const unsigned char* pCurrInst = startAt;
    size_t szRem = (mBase + mBaseSize) - addr;

    pDisasmdInst.detail = &pDisasmdDetail;

    while (cs_disasm_iter(mHandle, (const uint8_t**)&pCurrInst, &szRem, (uint64_t*)&addr, &pDisasmdInst))
    {
        if (callback(&pDisasmdInst) == false)
            break;
    }
}

void ICapstoneHelper::ForEachInstructionRel(uint64_t baseOffset, std::function<bool(cs_insn* pInst)> callback)
{
    ForEachInstructionAbs(mpBase + baseOffset, callback);
}
